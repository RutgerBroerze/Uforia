'''
Created on 11 mrt. 2013

@author: Jimmy van den Berg
'''

# This is the image module for PNG

#TABLE: Text:LONGTEXT, ICC_Profile:LONGTEXT, Interlace:LONGTEXT, Transparency:LONGTEXT, Gamma:LONGTEXT, DPIx:INT, DPIy:INT, Aspect:LONGTEXT, OtherInfo:LONGTEXT, XMPtag:LONGTEXT 

import sys, imp
from PIL import Image
import libxmp

# Load Uforia custom modules
try:
    config      = imp.load_source('config','include/config.py')
except:
    raise

def process(fullpath, columns=None):
        # Try to parse PNG data
        try:
            image = Image.open(fullpath, "r")
            
            assorted = [image.text]
            info_dictionary = image.info
            
            # Check if ICC profile is in info dictionary, if so put it in our list
            if "icc_profile" in info_dictionary:
                assorted.append(info_dictionary["icc_profile"])
                info_dictionary.pop("icc_profile")
            else:
                assorted.append(None)
            
            # Check if interlace is in info dictionary, if so put it in our list
            if "interlace" in info_dictionary:
                assorted.append(info_dictionary["interlace"])
                info_dictionary.pop("interlace")
            else:
                assorted.append(None)
            
            # Check if transparency is in info dictionary, if so put it in our list    
            if "transparency" in info_dictionary:
                assorted.append(info_dictionary["transparency"])
                info_dictionary.pop("transparency")
            else:
                assorted.append(None)
            
            # Check if gamma is in info dictionary, if so put it in our list      
            if "gamma" in info_dictionary:
                assorted.append(info_dictionary["gamma"])
                info_dictionary.pop("gamma")
            else:
                assorted.append(None)
            
            # Check if dpi is in info dictionary, if so put it in our list     
            if "dpi" in info_dictionary:
                assorted.append(info_dictionary["dpi"][0])
                assorted.append(info_dictionary["dpi"][1])
                info_dictionary.pop("dpi")
            else:
                assorted.append(None)
                assorted.append(None)
            
            # Check if aspect is in info dictionary, if so put it in our list                     
            if "aspect" in image.info:
                assorted.append(info_dictionary["aspect"])
                info_dictionary.pop("aspect")
            else:
                assorted.append(None)
                
            # If there are still other values in the dict then put those in column
            assorted.append(info_dictionary)
            
            # Delete variable
            del info_dictionary, image
            
            # Store the embedded XMP metadata
            xmpfile = libxmp.XMPFiles(file_path=fullpath)
            assorted.append(str(xmpfile.get_xmp()))
            xmpfile.close_file()
                
            # Make sure we stored exactly the same amount of columns as
            # specified!!
            assert len(assorted) == len(columns)
            
            # Print some data that is stored in the database if debug is true
            if config.DEBUG:
                print "\nPNG file data:"
                for i in range(0, len(assorted)):
                    print "%-18s %s" % (columns[i]+':', assorted[i])
                print
            
            return assorted
            
        except:
            print "An error occured while parsing image data: ", sys.exc_info()
        
            # Store values in database so not the whole application crashes
            return None