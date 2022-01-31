import logging
import struct 
import pefile
import sys
from icoextract import IconExtractor
import os
from pprint import pprint

'''
ICO Python Library
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ICO file format is an image file format for computer icons in Microsoft 
Windows. ICO files contain one or more small images at multiple sizes and 
color depths, such that they may be scaled appropriately.

This library provides functions to extract the individual image files from
Windows ICO files and the files metadata. 

File types supported include ICL, DLL, EXE and ICO. 
'''

# Copyright (c) 2022, Philip Young
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

__version__ = '1.0.0'
__author__ = 'Philip Young'
__license__ = "GPL"

__icotool_version__ = __version__

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

class IcoTool:
    def __init__(self, filename, output_folder=None):
        self.filename = filename
        self.output_folder = output_folder
        if output_folder and output_folder[-1] != '/':
            self.output_folder += "/"
        logger.debug("Reading {}".format(filename))
        with open(filename,'rb') as f:
            self.cur_file = f.read()
            self.file_bytes = bytearray(self.cur_file)
        self.determine_filetype()

    def set_output_folder(self, output_folder):
        logger.debug(f"Setting output folder to: {output_folder}")
        self.output_folder = output_folder

    def determine_filetype(self):
        idReserved = struct.unpack('<H',self.file_bytes[0:2])[0]
        idType = struct.unpack('<H',self.file_bytes[2:4])[0]

        self.icontype = "ICO"

        if idReserved != 0:
            e_lfanew =  struct.unpack('<I',self.file_bytes[60:64])[0]
            header_char = self.file_bytes[e_lfanew:e_lfanew+2].decode()

            if header_char not in ["NE","PE"]:
                logger.debug(f"File {self.filename} is not ICO, ICL, EXE, or DLL")
                raise Exception("File type not ICO, ICL, EXE, or DLL")

            if header_char == "NE":
                self.icontype = "NE"
            
            if header_char == "PE":
                self.icontype = "PE"
        logger.debug(f"Filetype is {self.icontype}")

    def extract_ico(self, index=None):
        logger.debug("Reading ICO file {}. Output Folder: {}. Index: {}".format(self.filename, self.output_folder, index))
        cur_bytes = bytearray(self.cur_file)

        if cur_bytes[0:2].decode() == "BM":
            raise "File provided is a bitmap"

        rtIconDir = False
        rtIconDirEntry = False
        ICONS = []
        
        idReserved = struct.unpack('<H',cur_bytes[0:2])[0]
        idType = struct.unpack('<H',cur_bytes[2:4])[0]
        idCount = struct.unpack('<H',cur_bytes[4:6])[0]
        loc = 6
        if idType == 1: # ICONS ONLY NO CURSORS
            name = os.path.splitext(os.path.basename(self.filename))[0]
            for i in range(0,idCount):
                
                #ICONDIRENTRY

                rtIconDirEntry = {
                    'bWidth'       : cur_bytes[loc], # Width, in pixels, of the image
                    'bHeight'      : cur_bytes[loc+1], # Height, in pixels, of the image
                    'bColorCount'  : cur_bytes[loc+2], # Number of colors in image (0 if >=8bpp)
                    'bReserved'    : cur_bytes[loc+3], # Reserved
                    'wPlanes'      : struct.unpack('<H',cur_bytes[loc+4:loc+6])[0], # Color Planes
                    'wBitCount'    : struct.unpack('<H',cur_bytes[loc+6:loc+8])[0], # Bits per pixel
                    'dwBytesInRes' : struct.unpack('<L',cur_bytes[loc+8:loc+12])[0], # how many bytes in this resource?
                    'dwImageOffset'  : struct.unpack('<L',cur_bytes[loc+12:loc+16])[0] # RT_ICON rnID
                }
                
                
                ICONHEADER = bytearray(2) + struct.pack('<H',1) + struct.pack('<H',1)
                IconDirectoryEntry = cur_bytes[loc:loc+12] + struct.pack('<L', 22)
                img = cur_bytes[rtIconDirEntry['dwImageOffset']:rtIconDirEntry['dwImageOffset']+rtIconDirEntry['dwBytesInRes']]

                if rtIconDirEntry['bColorCount'] == 0: rtIconDirEntry['bColorCount'] = 256
                if rtIconDirEntry['bWidth'] == 0: rtIconDirEntry['bWidth'] = 256
                if rtIconDirEntry['bHeight'] == 0: rtIconDirEntry['bHeight'] = 256

                if index is not None:
                    filename = "{}_{}_{}_{}x{}x{}.ico".format(name, index, i, rtIconDirEntry['bWidth'], rtIconDirEntry['bHeight'], rtIconDirEntry['bColorCount'])
                else:
                    filename = "{}_{}_{}x{}x{}.ico".format(name, i, rtIconDirEntry['bWidth'], rtIconDirEntry['bHeight'], rtIconDirEntry['bColorCount'])
                logger.debug(f"Export Filename:{filename}")
                if self.output_folder:
                    logger.info("Creating:", self.output_folder + filename)
                    f = open(self.output_folder + filename,"wb")
                    f.write(ICONHEADER+IconDirectoryEntry+img)
                    f.close()
                
                icon_dict = {
                    'filename': filename, 
                    'ID'      : i,
                    'Width'   : rtIconDirEntry['bWidth'],
                    'Height'  : rtIconDirEntry['bHeight'],
                    'Colors'  : rtIconDirEntry['bColorCount'],
                    'ICON': ICONHEADER+IconDirectoryEntry+img,
                    'original_filename' : self.filename,
                    'rtIconDirEntry' : rtIconDirEntry
                }
                
                if index is not None:
                    icon_dict['index'] = index

                ICONS.append(icon_dict)

                loc += 16

        return ICONS    

    def extract_icons_from_dll(self):
        # This function extracts icons from "NE" DLL files (and ICL files)
        # Returns a list of dicts with the file name containing the name, index, width, height, colors and the icon itself
        # This is kludgy as hell but it works

        # Mostly built off of:
        # https://www.codeproject.com/Articles/16178/IconLib-Icons-Unfolded-MultiIcon-and-Windows-Vista
        # https://hwiegman.home.xs4all.nl/fileformats/exe/WINHDR.TXT

        group_type = { 3: 'RT_ICON', 14 :'RT_GROUP_ICON' }
        ICONS = []

        dll_bytes = self.file_bytes
        
        logger.debug("Reading DLL/ICL/EXE file") 
        e_lfanew =  struct.unpack('<I',dll_bytes[60:64])[0]
        ne_header_char = dll_bytes[e_lfanew:e_lfanew+2].decode()
        logger.debug("Header Char: {}".format(ne_header_char))

        if ne_header_char == 'NE':
            logger.debug("Parsing NE DLL/ICL")

            ne_rsrctab = struct.unpack('<H',dll_bytes[e_lfanew+36:e_lfanew+36+2] )[0] + e_lfanew
            rscAlignShift = struct.unpack('<H',dll_bytes[ne_rsrctab:ne_rsrctab+2] )[0]
            resource_table = {'rscAlignShift':rscAlignShift, 'rscTypes': [], 'rscEndTypes' : 0, 'rscResourceNames': [], 'rscEndNames': 0}

            logger.debug("Offset from 0 to NE header (e_lfanew): {}".format(e_lfanew))
            logger.debug("Parsing Resource Tables (ne_rsrctab) at {} ({})".format(ne_rsrctab, hex(ne_rsrctab)))

            TNAMEINFO = []
            ptr = ne_rsrctab+2 #Advance ptr to TYPEINFO
            rttypeid = 1
            while rttypeid != 0 and rttypeid < 24:
                tmp_ba = dll_bytes[ptr:]
                rttypeid = struct.unpack('<H',tmp_ba[0:2] )[0] & 0x7FFF
                if rttypeid == 0 or rttypeid > 24: 
                    continue # At the end of the type info array exit
                rtresourcecount = struct.unpack('<H',tmp_ba[2:4] )[0]
                tmp_ba = dll_bytes[ptr+8:]
                if rttypeid in group_type:
                    logger.debug("Type ID {} has {} records ({}, {})".format(group_type[rttypeid], rtresourcecount, ptr+8, hex(ptr+8)))

                size = 0
                for x in range(0, rtresourcecount):

                    TNAMEINFO.append( {
                    'rttypeid' : rttypeid,
                    'rnOffset' : struct.unpack('<H',tmp_ba[size+ 0:size+2])[0] << rscAlignShift,
                    'rnLength' : struct.unpack('<H',tmp_ba[size+ 2:size+4])[0],
                    'rnFlags'  : struct.unpack('<H',tmp_ba[size+ 4:size+6])[0],
                    'rnID'     : struct.unpack('<H',tmp_ba[size+ 6:size+8])[0] & 0x7FFF,
                    'rnHandle' : struct.unpack('<H',tmp_ba[size+ 8:size+10])[0],
                    'rnUsage'  : struct.unpack('<H',tmp_ba[size+ 10:size+12])[0]
                    } )
                    
                    size = size + 12 #Skip ahead these entries
                ptr = ptr + size + 8 # Skip to the next TYPEINFO

            ptr = ptr + 2 # rscEndTypes
            tmp_ba = dll_bytes[ptr:]
            names = 0
            length = 1
            #Resource Names
            RESOURCENAMES = []

            while length != 0:
                length = tmp_ba[names]
                try:

                    RESOURCENAMES.append(tmp_ba[names+1:names+1+length].decode())
                except UnicodeDecodeError:
                    logger.debug("Could not decode resource name, unicode error")
                    pass
                names = names + tmp_ba[names] + 1
            
            resource_table['rscResourceNames'].extend(RESOURCENAMES)
            resource_table['rscTypes'].extend(TNAMEINFO)

            for GRPICONDIRENTRY in resource_table['rscTypes']:
                if GRPICONDIRENTRY['rttypeid'] == 14: #RT_GROUP_ICON    
                    try:
                        name = RESOURCENAMES[GRPICONDIRENTRY['rnID']]
                    except (KeyError, IndexError):
                        name = os.path.splitext(self.filename.split("/")[-1])[0]
                        logger.debug(f"Missing name, using {name}")
                        pass
                    if not name:
                        name = os.path.splitext(self.filename.split("/")[-1])[0]
                    idReserved = struct.unpack('<H',dll_bytes[GRPICONDIRENTRY['rnOffset']+0:GRPICONDIRENTRY['rnOffset']+2])[0]
                    idType = struct.unpack('<H',dll_bytes[GRPICONDIRENTRY['rnOffset']+2:GRPICONDIRENTRY['rnOffset']+4])[0]
                    idCount = struct.unpack('<H',dll_bytes[GRPICONDIRENTRY['rnOffset']+4:GRPICONDIRENTRY['rnOffset']+6])[0]
                    tmp_grp = dll_bytes[GRPICONDIRENTRY['rnOffset']+6:]
                    for x in range(0, idCount):
                        rtIcon = {
                        'bWidth'       : tmp_grp[0], # Width, in pixels, of the image
                        'bHeight'      : tmp_grp[1], # Height, in pixels, of the image
                        'bColorCount'  : tmp_grp[2], # Number of colors in image (0 if >=8bpp)
                        'bReserved'    : tmp_grp[3], # Reserved
                        'wPlanes'      : struct.unpack('<H',tmp_grp[4:6])[0], # Color Planes
                        'wBitCount'    : struct.unpack('<H',tmp_grp[6:8])[0], # Bits per pixel
                        'dwBytesInRes' : struct.unpack('<L',tmp_grp[8:12])[0], # how many bytes in this resource?
                        'nId'          : struct.unpack('<H',tmp_grp[12:14])[0] # RT_ICON rnID
                        }
                        
                        for RT_ICON in resource_table['rscTypes']:
                            if RT_ICON['rttypeid'] == 3 and  RT_ICON['rnID'] == rtIcon['nId']:
                                icon_file = bytearray(2) + struct.pack('<H',1) + struct.pack('<H',1)
                                ICONENTRY = tmp_grp[0:12] + struct.pack('<L', 22)
                                icon_bitmap = dll_bytes[RT_ICON['rnOffset']:RT_ICON['rnOffset']+rtIcon['dwBytesInRes']]
                                #print(ICONENTRY)
                                if rtIcon['bColorCount'] == 0: rtIcon['bColorCount'] = 256
                                filename = "{}_{}_{}x{}x{}.ico".format(name, GRPICONDIRENTRY['rnID'], rtIcon['bWidth'], rtIcon['bHeight'], rtIcon['bColorCount'])

                                # if folder:
                                #     logger.info("Creating: {}".format('', folder + filename))
                                #     f = open(folder + filename,"wb")
                                #     f.write(icon_file+ICONENTRY+icon_bitmap)
                                #     f.close()
                                logger.debug(f"Appending {filename}") 
                                ICONS.append({
                                    'filename': filename, 
                                    'ID'      : GRPICONDIRENTRY['rnID'],
                                    'Width'   : rtIcon['bWidth'],
                                    'Height'  : rtIcon['bHeight'],
                                    'Colors'  : rtIcon['bColorCount'],
                                    'ICON': icon_file+ICONENTRY+icon_bitmap,
                                    'original_filename' : self.filename,
                                    'rtIconDirEntry' : rtIcon
                                    })
                        tmp_grp = tmp_grp[14:]

        elif ne_header_char == "PE": 
            logger.debug("Parsing PE DLL/EXE")
            pe_icons = []
            
            try:
                extractor = IconExtractor(self.filename)
            
                for idx, entry in enumerate(extractor.list_group_icons()):
                    icon = extractor.get_icon(idx)
                    icon.seek(0)
                    iconfile = icon.read()
                    pe_icons.append({"id": idx, "icon": iconfile})
                
                tmp_curfile = self.cur_file

                for i in pe_icons:
                    self.cur_file = i['icon']
                    d = self.extract_ico(index=i['id'])
                    ICONS.append(d)

                self.cur_file = tmp_curfile
            except:
                pass
        return ICONS

    def flatten_pe(self, t):
        '''
        PE icon extract is a list of lists, this functions flattens them
        '''
        return [item for sublist in t for item in sublist]

    def best_icon(self, entries):
        b = 0
        w = 0
        best = None
        for i in range(len(entries)):
            icon = entries[i]
            if icon['Colors'] > b:
                b = icon['Colors']
                best = i
            if icon['Width'] > w and icon['Colors'] == b:
                w = icon['Width']
                b = icon['Colors']
                best = i
        logger.debug(f"Best icon {best}: {entries[best]['filename']}")
        return entries[best]

    def extract_all(self):
        '''
        Extracts all icons, returns a list of dicts with the format:
        'Colors': int,
        'Height': int,
        'ICON': bytearray(ICON FILE)
        'ID': int,
        'Width': int,
        'filename' : str,
        'rtIconDirEntry': dictionary of rtIconDirEntry
        (optional) 'Index': int
        '''

        if not self.icontype:
            raise ValueError(f"Icontype cannot be {self.icontype}")

        if self.icontype == "ICO":
            return self.extract_ico()
        elif self.icontype in ["NE", "PE"]:
            if self.icontype == "PE":
                return self.flatten_pe(self.extract_icons_from_dll())
            else:
                return self.extract_icons_from_dll()
        else:
            raise ValueError(f"Icon file type must be ICO, NE or PE: {self.icontype}")

    def extract_best(self):

        '''
        Extracts the best (highest quality) icons, returns a list of dicts with the format:
        'Colors': int,
        'Height': int,
        'ICON': bytearray(ICON FILE)
        'ID': int,
        'Width': int,
        'filename' : str,
        'rtIconDirEntry': dictionary of rtIconDirEntry,
        'original_filename' : str,
        (optional) 'Index': int
        '''

        best = []

        if not self.icontype:
            raise ValueError(f"Icontype cannot be {self.icontype}")

        if self.icontype == "ICO":
            return [self.best_icon(self.extract_ico())]
        elif self.icontype in ["NE", "PE"]:
            if self.icontype == "PE":
                for iconlist in self.extract_icons_from_dll():
                    best.append(self.best_icon(iconlist))
                return best
            else:
                return self.extract_icons_from_dll()

        else:
            raise ValueError(f"Icon file type must be ICO, NE or PE: {self.icontype}")