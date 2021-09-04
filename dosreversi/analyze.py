import re
import json
import struct
import sys
from operator import itemgetter
from dosreversi import MapFile
from capstone import *

"""dummy up version Three"""

LineComments = None
AboveComments = None
HexStringMatch = re.compile("0x[0-9a-fA-F]{1,4}")
MapFileAddrMatch = re.compile("^....:.... ")
FunctionNames = None
Code = None
ExportPrint = None # function to output to file or console

KnownVariables = {}
CsVariables = {}

SEG_SHIFT = 0

# Initialize Capstone
MD = Cs(CS_ARCH_X86, CS_MODE_16)
MD.skipdata = True

def dumpHeaders(hdr):
    bytesInLastPage,       = struct.unpack('<H',hdr[0x2:0x4])
    totalPages,            = struct.unpack('<H',hdr[0x4:0x6])
    numRelocationEntries,  = struct.unpack('<H',hdr[0x6:0x8])
    headerSize,            = struct.unpack('<H',hdr[0x8:0xa])

    relocationTableOffset, = struct.unpack('<H',hdr[0x18:0x1a])

    return {
        "bytesInLastPage": bytesInLastPage,
        "totalPages": totalPages,
        "numRelocationEntries": numRelocationEntries,
        "headerSize": headerSize,
        "relocationTableOffset": relocationTableOffset
    }

def get_raw_bytes(bytes):
    """helper to convert the bytearray returned by capstone into a hex string"""
    return ' '.join([f"{b:02x}" for b in bytes])

def get_raw_chars(bytes):
    return ''.join([chr(b) if (b < 127 and b > 31) else '.' for b in bytes])

def getCode(exe_filename, code_start = None, data_start = None):
    #Caller should catch FileNotFoundError
    with open(exe_filename, 'rb') as f:
        contents = f.read()

    if code_start is None:
        head = dumpHeaders(contents[:32])
        codeSize = ((head["totalPages"] - 1) * 512) + head["bytesInLastPage"]
        endOfHeader = head["headerSize"] * 16
        relocationTable = contents[head["relocationTableOffset"] : endOfHeader]

        binary = contents[endOfHeader : endOfHeader + codeSize]
    else:
        if data_start is None:
            binary = contents[code_start:]
        else:
            binary = contents[code_start:data_start]
    
    return binary

def seg_ofs_to_absolute(seg, ofs):
    return int(ofs,16) + (int(seg,16) * 16)

def is_retf(address, size, mnemonic, op_str):
    # helper to find the end of the last function
    return mnemonic == "retf"

def is_shl_bx(address, size, mnemonic, op_str):
    # helper to identify jump tables used in switch statements
    # bx is multiplied by 2 before jumping
    # because the jump table location size is 2 bytes
    return mnemonic == "shl" and op_str == "bx, 1"

def is_jmp_cs_bx_plus(address, size, mnemonic, op_str):
    return mnemonic == "jmp" and op_str.startswith("word ptr cs:[bx + ")

# capstone doesn't treat the offset as a UINT16LE
def is_jmp_cs_bx_minus(address, size, mnemonic, op_str):
    return mnemonic == "jmp" and op_str.startswith("word ptr cs:[bx - ")

def is_cmp_ax(address, size, mnemonic, op_str):
    return mnemonic == "cmp" and op_str.startswith("ax, ")

def is_cmp_bx(address, size, mnemonic, op_str):
    return mnemonic == "cmp" and op_str.startswith("bx, ")

def is_mov_ax_ptr_cs_bx(address, size, mnemonic, op_str):
    return mnemonic == "mov" and op_str == "ax, word ptr cs:[bx]"

def is_mov_bx(address, size, mnemonic, op_str):
    return mnemonic == "mov" and op_str.startswith("bx, ")

def is_mov_cx(address, size, mnemonic, op_str):
    return mnemonic == "mov" and op_str.startswith("cx, ")

def grab_jump_cs_bx_offset(address, size, mnemonic, op_str, seg):
    # "word ptr cs:[bx + " is 18 characters long.
    if op_str[16] == '-':
        return (65536 - int(op_str[18:-1], 16)) + (seg * 16)
    else:
        return int(op_str[18:-1], 16) + (seg * 16)

def find_jump_tables(disasm, seg):
    """return all jump tables offsets for this function so we don't diassemble them"""

    jump_tables = []

    # find the wacky jump tables that start with an id check
    for mov_ax_cs_i in [i for i,x in enumerate(disasm) if is_mov_ax_ptr_cs_bx(*x)]:
        if not is_mov_bx(*disasm[mov_ax_cs_i - 1]):
            continue

        if not is_mov_cx(*disasm[mov_ax_cs_i - 2]):
            continue

        # find bx offset
        op_str = disasm[mov_ax_cs_i - 1][3]
        local_ofs = int(op_str.split(' ')[-1], 16)
        abs_ofs = (seg * 16) + local_ofs

        # find cx count
        op_str = disasm[mov_ax_cs_i - 2][3]
        count = int(op_str.split(' ')[-1], 16)

        jump_tables.append( (abs_ofs, abs_ofs + (2 * count)) )
        jump_tables.append( (abs_ofs + (2 * count), abs_ofs + (4 * count)) )

    # find `shl bx, 1` that comes before a jump that we are interested in
    for shl_bx_i in [i for i,x in enumerate(disasm) if is_shl_bx(*x)]:
        # if not immediately followed by `jmp word ptr cs:[bx +]`
        if not (is_jmp_cs_bx_plus(*disasm[shl_bx_i+1])
            or is_jmp_cs_bx_minus(*disasm[shl_bx_i+1])):
            continue

        jt_ofs = grab_jump_cs_bx_offset(*disasm[shl_bx_i+1], seg)
        
        # jump table ~always~ comes after the jump
        if jt_ofs < disasm[shl_bx_i][0]:
            continue

        jt_end = None

        # now seek back to find the `cmp ax, __` to get the max size on the jump table
        for i in range(1,5):
            t = disasm[shl_bx_i - i]
            if is_cmp_ax(*t) or is_cmp_bx(*t):
                # times two because jump table offsets are word sized
                # plus one because the check is ~usually~ `ja`
                op_str = t[3]
                jt_end = 2 * (int(op_str.split(' ')[-1], 16) + 1)
                break

        if jt_end is not None:
            jump_tables.append( (jt_ofs, jt_ofs + jt_end) )

    return sorted(jump_tables)

def display_jump_table(jt_bytes):
    # must be a word alignment padding byte
    if (len(jt_bytes) % 2) == 1:
        jt_bytes = jt_bytes[1:]

    how_many_destinations = int(len(jt_bytes) / 2)


    # TODO: Sort by destination address
    # TODO: Deal with the jump destination endianness not being consistent
    ExportPrint(f" ~ JUMP TABLE ~ {how_many_destinations}")
    for i in range(how_many_destinations):
        addr, = struct.unpack('<H',jt_bytes[(i * 2) : (i * 2) + 2])
        ExportPrint(f"{i:3} -- {addr:04x}")

def csVariableSubstitute(op_str, seg, exact = False):
    if seg not in CsVariables:
        return op_str

    variableMatch = HexStringMatch.search(op_str)
    if variableMatch is not None:
        variableAddr = int(variableMatch[0], 16)
        if variableAddr in CsVariables[seg]:
            if not exact or (exact and ('+' not in CsVariables[seg][variableAddr])):
                op_str = HexStringMatch.sub(CsVariables[seg][variableAddr], op_str, 1)
            
    return op_str

def variableNameSubstitute(op_str, exact = False):
    variableMatch = HexStringMatch.search(op_str)
    if variableMatch is not None:
        variableAddr = int(variableMatch[0], 16)
        if variableAddr in KnownVariables:
            if not exact or (exact and ('+' not in KnownVariables[variableAddr])):
                op_str = HexStringMatch.sub(KnownVariables[variableAddr], op_str, 1)
            
    return op_str

def computeDestinationAddr(bs):
    """Jump or call relative to addr of following instruction"""
    instruction_len = len(bs)

    # Short jump versus near jump
    if bs[0] == 15:
        addr_bs = bs[2:]
    else:
        addr_bs = bs[1:]

    if len(addr_bs) == 1:
        t = struct.unpack('<b', addr_bs)
    elif len(addr_bs) == 2:
        t = struct.unpack('<h', addr_bs)
    elif len(addr_bs) == 4:
        t = struct.unpack('<l', addr_bs)
    else:
        t = (0)

    # Just to be on the safe side.
    if type(t) is tuple:
        return t[0] + instruction_len
    else:
        return 0

def print_asm_line(seg, ofs, function_start, line):
    abs_ofs = ofs + (seg*16)
    op_str = line.op_str

    # replace variable address with known variable name
    if ("bp -" not in op_str) and ("bp +" not in op_str):
        if ("ptr cs:" in op_str):
            op_str = csVariableSubstitute(op_str, seg)
        elif ("ptr" in op_str): 
            op_str = variableNameSubstitute(op_str)
        elif (line.mnemonic == "lcall") and ("[" in op_str):
            op_str = variableNameSubstitute(op_str)
        elif (line.mnemonic in ['mov', 'add']) and (op_str.startswith('di')):
            op_str = variableNameSubstitute(op_str, True)

    BaseString = f"{seg+SEG_SHIFT:04x}:{ofs:04x} (0x{abs_ofs:05x}) : {get_raw_bytes(line.bytes):20}  {line.mnemonic} {op_str}"
    extras = []

    # Call offsets apparently ignore the given starting offset of disassembly
    if line.mnemonic == 'call':
        # not a function pointer call or something else
        if line.op_str.startswith('0x'):
            # mod 65536 if the offset is negative and wraps around the seg.
            true_offset = abs_ofs + computeDestinationAddr(line.bytes) % 0x10000

            if true_offset in FunctionNames:
                func_name = FunctionNames[true_offset]
            else:
                func_name = "?"
                
            extras.append( f"#{func_name}" )

    elif line.mnemonic == 'lcall':
        if line.op_str.startswith('0'):
            lcall_dest_a = [int(x,16) for x in line.op_str.split(':')]
            lcall_dest = lcall_dest_a[1] + lcall_dest_a[0] * 16 

            if lcall_dest in FunctionNames:
                func_name = FunctionNames[lcall_dest]
            else:
                func_name = "?"

            #print(f"{seg+SEG_SHIFT:04x}:{ofs:04x} (0x{abs_ofs:05x}) : {get_raw_bytes(line.bytes):20}  {line.mnemonic} {line.op_str} #{func_name}")
            extras.append( f"#{func_name}" )
            #print(f"{BaseString} #{func_name}")
            #return


    elif line.mnemonic.startswith('j'):
        corrected_jump_offset = computeDestinationAddr(line.bytes)
        if corrected_jump_offset < 0:
            jump_notice = f"$ jump up {-1 * corrected_jump_offset}"
        else:
            jump_notice = f"$ jump down {corrected_jump_offset}"

        extras.append(jump_notice)

    if abs_ofs in LineComments:
        extras.append(f"; {LineComments[abs_ofs]}")

    #print(f"{seg+SEG_SHIFT:04x}:{ofs:04x} (0x{abs_ofs:05x}) : {get_raw_bytes(line.bytes):20}  {line.mnemonic} {line.op_str} {comment}")

    if abs_ofs in AboveComments:
        ExportPrint(f"; {AboveComments[abs_ofs]}")

    ExportPrint(f"{BaseString} {' '.join(extras)}")

def disassemble(binary, seg, absolute_offset, options):    
    sections = []

    if "jump_table" in options:
        lastCodeOfs = 0

        for i in range(len(options["jump_table"])):
            (js,je) = options["jump_table"][i]
            sections.append( (lastCodeOfs, js-absolute_offset, 'code') )
            sections.append( (js-absolute_offset, je-absolute_offset, 'jumps') )
            lastCodeOfs = je-absolute_offset

        sections.append( (lastCodeOfs, len(binary), 'code') )

    else:
        sections.append( (0, len(binary), 'code') )

    for (tStart, tEnd, tType) in sections:
        if tStart >= tEnd:
            continue

        if tType == 'code':

            code_only = binary[tStart : tEnd]

            # has to be absolute_offset here so the address reference is correct.
            lines = list(MD.disasm(code_only, absolute_offset + tStart))

            for line in lines:
                local_ofs = line.address - (seg*16)
                print_asm_line(seg, local_ofs, absolute_offset, line)

        elif tType == 'jumps':
            display_jump_table(binary[tStart : tEnd])

def displayBinaryData(binary, seg, absolute_offset):
    #TODO
    #abs_ofs = ofs + (seg*16)
    #BaseString = f"{seg+SEG_SHIFT:04x}:{ofs:04x} (0x{abs_ofs:05x}) : {get_raw_bytes(line.bytes):20}  {line.mnemonic} {line.op_str}"
    ofs = absolute_offset - (seg << 4)

    for i in range(int(len(binary)/16)+1):
        row = binary[i*16 : (i+1)*16]
        ExportPrint(f"{seg+SEG_SHIFT:04x}:{ofs + (i*16):04x} : {get_raw_bytes(row):48}  {get_raw_chars(row):16}")

def first_pass(binary, seg, absolute_offset, find_end = False):
    options = {}
    disasm = [detail for detail in MD.disasm_lite(binary, absolute_offset)]

    if find_end:
        retfs = [i for i,x in enumerate(disasm) if is_retf(*x)]
        if len(retfs) > 0:
            last_addr = disasm[retfs[0] + 1][0]
            binary = binary[: (last_addr - absolute_offset)]

    jump_table = find_jump_tables(disasm, seg)
    if len(jump_table) > 0:
        options["jump_table"] = jump_table

    disassemble(binary, seg, absolute_offset, options)

def do_one_function(function_info):
    # if it's to be ignored
    if function_info['name'].startswith('/'):
        return

    # if it's raw string data
    if function_info['name'].startswith('~'):
        ExportPrint(f"{ function_info['name'] }")

        if function_info["end"] is not None:
            excerpt = Code[function_info["abs"] : function_info["end"]]
        else:
            excerpt = Code[function_info["abs"] : ]

        displayBinaryData(excerpt, function_info['seg'], function_info['abs'])

    else:
        ExportPrint(f"#{ function_info['name'] }")

        if function_info["end"] is not None:
            excerpt = Code[function_info["abs"] : function_info["end"]]
            first_pass(excerpt, function_info["seg"], function_info["abs"])
        else:
            excerpt = Code[function_info["abs"] : ]
            first_pass(excerpt, function_info["seg"], function_info["abs"], True)

def just_start_disassembling(function_info):
    ExportPrint(f"#{ function_info['name'] }")

    excerpt = Code[function_info["abs"] : ]
    first_pass(excerpt, function_info["seg"], function_info["abs"])

def read_map_file(map_filename, isPascal):
    x = MapFile(map_filename, isPascal)
    return x.export()

def get_function_map(map_file):
    # The map file tells us where each function starts.
    # Last function_end is None because we may have to just figure that one out on the fly
    functions = [{
        "seg": int(seg,16),
        "abs": seg_ofs_to_absolute(seg,ofs),
        "name": function_name,
        "end": None
        } for seg,ofs,function_name in map_file]

    function_starts = [seg_ofs_to_absolute(seg,ofs) for seg,ofs,name in map_file]
    function_ends = function_starts[1:] + [None]
    
    for i, end in enumerate(function_ends):
        functions[i]["end"] = end

    return functions

def read_comments(comment_filename):
    same_line = {}
    above_line = {}
    with open(comment_filename, 'r') as f:
        lines = [line.strip() for line in f]
    
    for line in lines:
        if line.startswith('//'):
            continue
        
        if len(line) == 0:
            continue

        if ';' in line:
            [addr, comment] = line.split(';', 2)
            same_line[int(addr, 16)] = comment.strip()
        elif '^' in line:
            [addr, comment] = line.split('^', 2)
            above_line[int(addr, 16)] = comment.strip() 

    return (same_line, above_line)

def useMapFileForVariables(mapFileTuples):
    global KnownVariables

    # short of something more sophisticated, using the last seg will do
    dataSeg = mapFileTuples[-1][0]
    dataSymbols = [t for t in mapFileTuples if t[0] == dataSeg]
    lastSymbol = dataSymbols[-1]

    # another hack, but assume the last thing is a 4 byte pointer
    lastSymbolEstimatedEnd = f"{int(lastSymbol[1], 16) + 4:04X}"
    dataSymbolEnds = dataSymbols[1:] + [(dataSeg, lastSymbolEstimatedEnd, 'END')]
    
    symbolStartEnd = zip(dataSymbols, dataSymbolEnds)

    for (tStart,tEnd) in symbolStartEnd:
        estSize = int(tEnd[1], 16) - int(tStart[1], 16)
        startsAt = int(tStart[1], 16)
        name = tStart[2]
        #print(f"{name:40}{estSize}")
        KnownVariables[startsAt] = f"*{name}"
        for i in range(1, int(estSize)):
            KnownVariables[startsAt+i] = f"*{name}+{i}"

def createKnownVariables(variableFile):
    global KnownVariables
    global CsVariables

    with open(variableFile, 'r') as f:
        for line in f:
            # support comments
            if line.startswith('//'):
                continue

            # support blank lines
            if len(line.strip()) == 0:
                continue

            a = line.strip().split(',')
            if len(a) == 3:
                [start, count, name] = a

                # if code segment variable
                if ':' in start:
                    [seg,ofs] = start.split(':', 2)
                    d_seg = int(seg, 16)
                    d_ofs = int(ofs, 16)
                    if d_seg not in CsVariables:
                        CsVariables[d_seg] = {}

                    CsVariables[d_seg][d_ofs] = f"*{name}"
                    for i in range(1, int(count)):
                        CsVariables[d_seg][d_ofs+i] = f"*{name}+{i}"

                # else data segment variable
                else:
                    start = int(start, 16)
                    KnownVariables[start] = f"*{name}"
                    for i in range(1, int(count)):
                        KnownVariables[start+i] = f"*{name}+{i}"

def getArg():
    """Get the first command line argument if there is one"""

    if len(sys.argv) == 1:
        return None

    return sys.argv[1]

def getRelocationTable(contents):
    header = dumpHeaders(contents[:32])
    ofs = header['relocationTableOffset']
    siz = header['numRelocationEntries'] * 4
    table = contents[ofs : ofs + siz]
    output = []

    for i in range(header['numRelocationEntries']):
        (ofs, seg) = struct.unpack('<HH', table[i*4 : (i*4) + 4])
        output.append( (seg,ofs) )
    return output

def find_near_calls(mapFileName):
    result = []
    x = MapFile(mapFileName, False)
    for seg in x.segs:
        if seg.type != 'CODE': continue

        # skip these because we might not have code available for them
        # (you have to use a custom-build TPL that makes the symbols all public)
        if seg.name in ['Dos', 'System', 'Crt']: continue

        # hack
        knownOfs = x.publicMap[seg.start[:-1]]

        cs = Code[int(seg.start,16) : int(seg.stop,16)]
        lines = MD.disasm_lite(cs, int(seg.start, 16))
        howFarIn = 0
        for (address, size, mnemonic, op_str) in lines:
            howFarIn += size
            if mnemonic == "call" and op_str.startswith('0x'):
                # reconstitute the bytes of the instruction
                bs = cs[(howFarIn-size) : howFarIn]
                delta, = struct.unpack('<h', bs[1:])

                # 3 bytes (length of call instruction) already added
                newFunctionOfs = howFarIn + delta

                #print(f"{mnemonic} {op_str:8} {list(bs)} {delta:5} {newFunctionOfs:04x}")

                if newFunctionOfs < 0:
                    print(f"neg {mnemonic} {op_str}")
                    continue

                if (int(seg.start,16) + newFunctionOfs) > int(seg.stop, 16):
                    print(f"ovr {mnemonic} {op_str}")
                    continue

                newFunctionOfsName = f"{newFunctionOfs:04X}"
                
                # skip if we have it already
                if newFunctionOfsName in knownOfs:
                    continue

                knownOfs[newFunctionOfsName] = ""

                absName = f".fn{int(seg.start,16) + newFunctionOfs:x}"
                v = (seg.start[:-1], newFunctionOfsName, absName)
                result.append(v)

    return result

def useRelocationTableToFindFarcalls(contents):
    table = getRelocationTable(contents)

    """ lcalls look like this:
    9a f0 08 b1 03        lcall 0x3b1:0x8f0
    9a opcode, followed by two words, offset and segment.
    the relocation table points at the segment word
    because that's the thing that is "relocated"
    """

    farcallDestinations = []

    for (seg, ofs) in table:
        absolutePos = (seg << 4) + ofs
        (opcode, lcallOfs, lcallSeg) = struct.unpack('<BHH', Code[absolutePos - 3: absolutePos + 2])
        #print(f"{lcallSeg:04x}:{lcallOfs:04x}")

        # make sure it's an absolute lcall
        # relocation table could point to references to the dataseg
        if opcode == 0x9a:
            farcallDestinations.append((f"{lcallSeg:04X}",f"{lcallOfs:04X}"))

    return farcallDestinations

class MapperSettings:
    def __init__(self, obj):
        # required
        self.exeFile = obj['exe-file']
        self.mapFile = obj.get('map-file', '')

        self.outFile = obj.get('out-file')
        self.commentFile = obj.get('comment-file')
        self.isPascal = obj.get('pascal', False)
        self.variableFile = obj.get('variable-file', None)
        self.mapFileVariables = obj.get('map-file-variables', False)
        self.codeStart = obj.get('code-start', None)
        self.dataStart = obj.get('data-start', None)
        
        if type(self.mapFileVariables) is not bool:
            self.mapFileVariables = bool(self.mapFileVariables)

        if self.codeStart is not None and type(self.codeStart) is str:
            self.codeStart = int(self.codeStart, 16)

        if self.dataStart is not None and type(self.dataStart) is str:
            self.dataStart = int(self.dataStart, 16)

def analyze_code(settingsInput):
    global Code
    global LineComments
    global AboveComments
    global FunctionNames
    global ExportPrint

    settings = MapperSettings(settingsInput)

    try:
        map_file = read_map_file(settings.mapFile, False) #removed settings.isPascal
    except FileNotFoundError:
        exit(f"map file '{settings.mapFile}' not found")

    try:
        (LineComments, AboveComments) = read_comments(settings.commentFile)
    except:
        LineComments = {}
        AboveComments = {}

    if settings.mapFileVariables:
        useMapFileForVariables(map_file)
    elif settings.variableFile is not None:
        createKnownVariables(settings.variableFile)

    try:
        # Global because maybe it's faster than passing the array around?
        Code = getCode(settings.exeFile, settings.codeStart, settings.dataStart)
    except FileNotFoundError:
        exit(f"exe file '{settings.exeFile}' not found")

    # pascal likes to hide the functions on you
    # use the relocation table to find all farcalls
    # mark any call destinations that are not in the map file
    if settings.isPascal:
        with open(settings.exeFile, 'rb') as f:
            contents = f.read()
        allFarcalls = useRelocationTableToFindFarcalls(contents)
        callsWeHave = [(x[0],x[1]) for x in map_file]
        for call in allFarcalls:
            if call not in callsWeHave:
                newName = f"#.fn{seg_ofs_to_absolute(call[0], call[1])}"
                if (call[0],call[1],newName) not in map_file:
                    map_file.append((call[0],call[1],newName))

        # now find the near calls.
        for seg,ofs,function_name in find_near_calls(settings.mapFile):
            map_file.append((seg, ofs, function_name))

        map_file = sorted(map_file, key=itemgetter(0,1))

    # Global variable. Used to reference each function by name during the disassembly
    FunctionNames = { seg_ofs_to_absolute(seg,ofs) : function_name for seg,ofs,function_name in map_file }

    fmap = get_function_map(map_file)

    # TODO: this sucks
    if settings.outFile is not None:
        with open(settings.outFile, 'w+') as f:
            ExportPrint = lambda line: f.write(f"{line}\n")

            if len(fmap) == 1:
                # Just disassemble from code_start to data_start.
                just_start_disassembling(fmap[0])
            else:
                for x in fmap:
                    do_one_function(x)
    else:
        ExportPrint = print
        for x in fmap:
            do_one_function(x)
