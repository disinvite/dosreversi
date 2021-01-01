import re
#import json
import os
from operator import itemgetter

PascalSegUnits = ['Crt', 'System']
MyPascalSegMatch = re.compile(r"^\~?(.+):([0-9a-fA-F]{4})\s*(.+)$")
SegMatch = re.compile(r"^([0-9A-F]{5})H ([0-9A-F]{5})H ([0-9A-F]{5})H (.+?)\s*([A-Z]*)$")
PublicMatch = re.compile(r"\s*^([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\s*(\S*)$")

class SegEntry:
    def __init__(self, match):
        self.start   = match.group(1)
        self.stop    = match.group(2)
        self.length  = match.group(3)
        self.name    = match.group(4)
        self.type    = match.group(5)

    def __str__(self):
        return f"{self.start} {self.stop} {self.length} {self.name} {self.type}"

"""
class PublicEntry:
    def __init__(self):
        pass
"""

class MapFile:
    def __init__(self, filename, isPascal = False):
        self.filename = filename
        self.segs = []
        self.publicMap = {}
        self.isPascal = isPascal
        self.reload()

    def loadPascalFile(self):
        """Load segment offsets determined by hand for pascal built-in units"""
        """i.e. crt, system"""

        moduleDir = os.path.dirname(__file__)
        segFile = os.path.join(moduleDir, 'pascal-unit-segs.txt')

        try:
            with open(segFile, 'r') as f:
                lines = [line.strip() for line in f]
        except FileNotFoundError:
            # TODO
            return {}

        result = {}

        for line in lines:
            match = MyPascalSegMatch.match(line)
            if match is None:
                continue
            segName = match.group(1)
            segOfs = match.group(2)
            publicName = match.group(3)

            if segName not in result:
                result[segName] = {}

            result[segName][segOfs] = publicName

        return result

    def reload(self):
        with open(self.filename, 'r') as f:
            lines = [line.strip() for line in f]

        self.segs = [SegEntry(item) for item in map(SegMatch.match, lines) if item is not None]

        # Because there could be "publics by name" and "publics by value" in the file
        # We want "publics by value"
        publicUnique = set([line for line in lines if PublicMatch.match(line)])
        for line in publicUnique:
            match = PublicMatch.match(line)
            if match is None:
                continue

            segName = match.group(1)
            segOfs = match.group(2)
            publicName = match.group(3)

            if segName not in self.publicMap:
                self.publicMap[segName] = {}

            self.publicMap[segName][segOfs] = publicName

        # if it's a pascal map file, try to replace the built-in units with the file we have
        if self.isPascal:
            pascalUnits = self.loadPascalFile()

            for seg in self.segs:
                if seg.name in PascalSegUnits:
                    # hack off the last character (hopefully a zero)
                    UnitSegNumber = seg.start[:-1]
                    
                    # if we have some publics from that seg, just replace them all
                    if UnitSegNumber in self.publicMap:
                        del self.publicMap[UnitSegNumber]
                    
                    self.publicMap[UnitSegNumber] = pascalUnits[seg.name]

    def export(self):
        #print(json.dumps(self.publicMap, indent=4))
        result = []
        for seg in self.publicMap:
            for ofs in self.publicMap[seg]:
                t = (seg, ofs, self.publicMap[seg][ofs])
                result.append(t)

        return sorted(result, key=itemgetter(0,1))

"""
if __name__ == '__main__':
    x = MapFile('/dos/pascal/thicc.map', True)
    y = x.export()
"""
