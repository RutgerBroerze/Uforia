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

# This is the module for handling rfc822 email types

# Do not change from CamelCase because these are the official header names
# TABLE: Delivered_To:LONGTEXT, Original_Recipient:LONGTEXT, Received:LONGTEXT, Return_Path:LONGTEXT, Received_SPF:LONGTEXT, Authentication_Results:LONGTEXT, DKIM_Signature:LONGTEXT, DomainKey_Signature:LONGTEXT, Organization:LONGTEXT, MIME_Version:DOUBLE, List_Unsubscribe:LONGTEXT, X_Received:LONGTEXT, X_Priority:LONGTEXT, X_MSMail_Priority:LONGTEXT, X_Mailer:LONGTEXT, X_MimeOLE:LONGTEXT, X_Notifications:LONGTEXT, X_Notification_ID:LONGTEXT, X_Sender_ID:LONGTEXT, X_Notification_Category:LONGTEXT, X_Notification_Type:LONGTEXT, X_UB:INT, Precedence:LONGTEXT, Reply_To:LONGTEXT, Auto_Submitted:LONGTEXT, Message_ID:LONGTEXT, Date:DATE, Subject:LONGTEXT, From:LONGTEXT, To:LONGTEXT, Content_Type:LONGTEXT, XTo:LONGTEXT, Xcc:LONGTEXT, Xbcc:LONGTEXT, Cc:LONGTEXT, Bcc:LONGTEXT, content:LONGTEXT, Attachments:LONGTEXT, SpamScore:DOUBLE, SpamReport:LONGTEXT, isSpam:bool

#Configuration for the SpamAssassin
SPAMD_HOST = '127.0.0.1'
SPAMD_PORT = 783
SPAMD_USER = 'spamd'
SPAMD_SPAMSCORELIMIT = 1.0
SPAMD_DOSPAMCHECK = True

import os
import sys
import traceback
import shutil
import pyzmail
import recursive
import tempfile
import python_dateutil.dateutil.parser as date_parser
import socket

def process(file, config, rcontext, columns=None):
        fullpath = file.fullpath

        # Try to parse rfc822 data
        try:
            #  Get the e-mail headers from a file
            email_file = open(fullpath, 'r')
            msg = pyzmail.PyzMessage.factory(email_file)

            # find all attachments and save them to a temp folder
            tempdir = None
            attachments = []
            try:
                tempdir = tempfile.mkdtemp(dir=config.EXTRACTDIR)
                for mailpart in msg.mailparts:

                    if not mailpart.is_body:
                        attachments.append(mailpart.filename)
                        f = open(os.path.join(tempdir, mailpart.filename), 'wb')
                        if mailpart.type.startswith('text/') and mailpart.charset is not None:
                            f.write(mailpart.get_payload().decode(mailpart.charset))
                        else:
                            f.write(mailpart.get_payload())
                        f.close()
                if len(attachments) > 0:
                    recursive.call_uforia_recursive(config, rcontext, tempdir, fullpath)
            except:
                traceback.print_exc(file=sys.stderr)
            finally:
                try:
                    if tempdir:
                        shutil.rmtree(tempdir)  # delete directory
                except OSError as exc:
                    traceback.print_exc(file=sys.stderr)

            # Get most common headers
            assorted = [msg.get_decoded_header("Delivered-To", None),
                        msg.get_decoded_header("Original-Recipient", None),
                        msg.get_decoded_header("Received", None),
                        msg.get_decoded_header("Return-Path", None),
                        msg.get_decoded_header("Received-SPF", None),
                        msg.get_decoded_header("Authentication-Results", None),
                        msg.get_decoded_header("DKIM-Signature", None),
                        msg.get_decoded_header("DomainKey-Signature", None),
                        msg.get_decoded_header("Organization", None),
                        msg.get_decoded_header("MIME-Version", None),
                        msg.get_decoded_header("List-Unsubscribe", None),
                        msg.get_decoded_header("X-Received", None),
                        msg.get_decoded_header("X-Priority", None),
                        msg.get_decoded_header("X-MSMail-Priority", None),
                        msg.get_decoded_header("X-Mailer", None),
                        msg.get_decoded_header("X-MimeOLE", None),
                        msg.get_decoded_header("X-Notifications", None),
                        msg.get_decoded_header("X-Notification-ID", None),
                        msg.get_decoded_header("X-Sender-ID", None),
                        msg.get_decoded_header("X-Notification-Category", None),
                        msg.get_decoded_header("X-Notification-Type", None),
                        msg.get_decoded_header("X-UB", None),
                        msg.get_decoded_header("Precedence", None),
                        msg.get_decoded_header("Reply-To", None),
                        msg.get_decoded_header("Auto-Submitted", None),
                        msg.get_decoded_header("Message-ID", None),
                        date_parser.parse(msg.get_decoded_header("Date", None)),
                        msg.get_decoded_header("Subject", None),
                        msg.get_decoded_header("From", None),
                        msg.get_decoded_header("To", None),
                        msg.get_decoded_header("Content-Type", None),
                        msg.get_decoded_header("X-To", None),
                        msg.get_decoded_header("X-Cc", None),
                        msg.get_decoded_header("X-Bcc", None),
                        msg.get_decoded_header("Cc", None),
                        msg.get_decoded_header("Bcc", None)]

            # Start at the beginning of the file
            email_file.seek(0)

            # Put whole email file in database
            assorted.append(email_file.read())

            assorted.append(','.join(attachments))

            #SPAMCHECK
            if SPAMD_DOSPAMCHECK:
                email_file_temp = email_file
                email_file_temp.seek(0)
                email_use = email_file_temp.read()

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    print "socket created"
                    sock.connect((SPAMD_HOST, SPAMD_PORT))
                    print "socket connected"

                    output = []

                    output.append('REPORT SPAMC/1.2')
                    output.append('Content-length: %d' % len(email_use))
                    output.append('User: %s' % SPAMD_USER)
                    output.append('')
                    output.append(email_use)

                    data = '\r\n'.join(output)
                    del output[:]
                    sock.sendall(data);
                    print 'data sent'

                    fd = sock.makefile('rb', 0)

                    spamd_header = fd.readline()
                    if spamd_header.find('EX_OK') == -1:
                        raise Exception

                    spamd_score = fd.readline()
                    spamd_score_splitted = spamd_score.split(";")[1].split("/")[0].strip()

                    saveReport = False
                    report = ''
                    for line in fd.readlines():
                        if saveReport:
                            report += line

                        if line.startswith('----'):
                            saveReport = True

                    assorted.append(spamd_score_splitted)
                    assorted.append(report)

                    #print '!!!'
                    #print spamd_score_splitted
                    #print '!!!'
                    #print SPAMD_SPAMSCORELIMIT
                    #print '!!!'

                    if float(spamd_score_splitted) > SPAMD_SPAMSCORELIMIT:
                        assorted.append(1)
                    else:
                        assorted.append(0)

                    #print '---2!!!---'
                    #print spamd_header
                    #print spamd_score
                    #print '---!!2--'
                    #print spamd_score_splitted
                    #print '---2!!!---'

                    sock.close
                    #print "socket closed"
                except Exception:
                    print 'SpamCheck error'
                    traceback.print_exc(file=sys.stderr)
            else:
                assorted.append(None);
                assorted.append(None);
                assorted.append(0);
            #SPAMCHECK

            # Make sure we stored exactly the same amount of columns as
            # specified!!
            assert len(assorted) == len(columns)

            # Print some data that is stored in the database if debug is true
            if config.DEBUG:
                print "\nrfc822 file data:"
                for i in range(0, len(assorted)):
                    print "%-18s %s" % (columns[i] + ':', assorted[i])

            return assorted
        except TypeError:
            print('TypeError')
            pass
        except:
            traceback.print_exc(file=sys.stderr)

            # Store values in database so not the whole application crashes
            return None
