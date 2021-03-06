#!/usr/bin/env python

# Copyright (C) 2013 Hogeschool van Amsterdam

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# This is the image module for TGA

# TABLE: tile:LONGTEXT, compression:LONGTEXT, orientation:INT, other_info:BLOB, XMP:LONGTEXT

import sys
import traceback
from PIL import Image


def process(file, config, rcontext, columns=None):
        fullpath = file.fullpath
        # Try to parse TGA data
        try:
            image = Image.open(fullpath, "r")

            assorted = [image.tile]
            info_dictionary = image.info

            # Check if compression is in info dictionary,
            # if so put it in our list
            if "compression" in info_dictionary:
                assorted.append(info_dictionary["compression"])
                info_dictionary.pop("compression")
            else:
                assorted.append(None)

            # Check if orientation is in info dictionary,
            # if so put it in our list
            if "orientation" in info_dictionary:
                assorted.append(info_dictionary["orientation"])
                info_dictionary.pop("orientation")
            else:
                assorted.append(None)

            # If there are still other values in the
            # dict then put those in column
            assorted.append(info_dictionary)

            # Delete variable
            del image, info_dictionary

            # Store the embedded XMP metadata
            if config.ENABLEXMP:
                import libxmp
                xmpfile = libxmp.XMPFiles(file_path=fullpath)
                assorted.append(str(xmpfile.get_xmp()))
                xmpfile.close_file()
            else:
                assorted.append(None)

            # Make sure we stored exactly the same amount of columns as
            # specified!!
            assert len(assorted) == len(columns)

            # Print some data that is stored in the database if debug is true
            if config.DEBUG:
                print "\nTGA file data:"
                for i in range(0, len(assorted)):
                    print "%-18s %s" % (columns[i], assorted[i])
                print

            return assorted

        except:
            traceback.print_exc(file=sys.stderr)

            # Store values in database so not the whole application crashes
            return None
