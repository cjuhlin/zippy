#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MIT License
# Copyright (c) 2020 Christopher Juhlin <opensource@nebi.se>
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#title           :zippy.py
#description     :Unpack and bruteforce zip password with help of wordlist
#author          :Christopher Juhlin
#date            :20200425
#version         :0.1
#usage           :python3 zippy.py
#notes           : Made for a CTF-challenge , Zip-a-Dee-Doo-Dah @ houseplant 2020.
#python_version  :3.7
#==============================================================================
import random
import string
import zipfile
import tarfile
import gzip
from pathlib import Path
import shutil
import magic
import argparse
import logging
import coloredlogs

# Construct the argument parser
ap = argparse.ArgumentParser()

# Add the arguments to the parser
ap.add_argument("-w", "--wordlist",
                required=False,
                help="wordlist with password")
ap.add_argument("-a", "--archive",
                required=True,
                help="archive file to decompress")
# Optional verbosity counter (eg. -v, -vv, -vvv, etc.)
ap.add_argument("-log", "--log",
                default="info",
                help=("Provide logging level. "
                        "Example --log debug', default='info'"),
                )
args = vars(ap.parse_args())
print(args)


levels = {
    "critical": logging.CRITICAL,
    "error": logging.ERROR,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
}
level = levels.get(args["log"].lower())
if level is None:
    raise ValueError(
        f"log level given: {args['log']}"
        f" -- must be one of: {' | '.join(levels.keys())}"
    )
logging.basicConfig(level=level)
logger = logging.getLogger(__name__)
coloredlogs.install(level=level)
coloredlogs.install(level=level, logger=logger)


def randomString(stringLength=16):
    """
    Create random string
    Parameters:
    stringLength (int): Length of the randomstring
    Returns:
    str: Return a randomstring
    """
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(stringLength))


def guesspass(archive_file, wordlist):
    """
    Trying to bruteforce password for zipfile with help of your wordlist
    Parameters:
    archive_file (str): filepath to the archive file
    wordlist (str): filepath to the wordlist
    Returns:
    str: Return the unpacked filename path if it succesfull
        bruteforce the password.
    """
    # initialize the Zip File object
    filename = archive_file
    archive_file = zipfile.ZipFile(archive_file)
    # count the number of words in this wordlist
    try:
        n_words = len(list(open(wordlist, "rb")))
        workdir = Path(filename).parents[0]
        logger.info(f"Total passwords to test: {n_words}")
    except Exception as e:
        logger.debug(f"Exception raised: {e}")
    with open(wordlist, "rb") as wordlist:
        for word in wordlist:
            try:
                archive_file.extractall(workdir, pwd=word.strip())
            except Exception as e:
                if "password" in str(e):
                    continue
                else:
                    logger.debug(f"Exception raised: {e}")
                    continue
            else:
                password = word.decode().strip()
                logger.info(f"[+] Password for {filename}found:{password}")
                filelist = archive_file.namelist()
                if filelist:
                    return str(workdir) + "/" + str(filelist[0])
    logger.info("[!] Password not found, try other wordlist.")
    return None


def unpacking(filename):
    """
    Unpacking archive file of diffrent kinds.
    Parameters:
    filename (str): filepath to the archive file
    Returns:
    str: Return the unpacked filename path.
    """

    fname = Path(filename).stem
    Path(filename).suffix
    guessfile = magic.detect_from_filename(filename).mime_type
    logger.info(f"Working on file {filename} , Mime type: {guessfile}")
    workdir = Path(filename).parents[0]
    if "application/zip" in guessfile:
        with zipfile.ZipFile(filename, "r") as zip_ref:
            try:
                zip_ref.extractall(workdir)
                filelist = zip_ref.namelist()
                if filelist:
                    result = str(workdir) + "/" + str(filelist[0])
            except RuntimeError as e:
                if "encrypted" in str(e):
                    result = guesspass(filename, args["wordlist"])
                else:
                    print(e)
    elif "application/gzip" in guessfile:
        with gzip.open(filename, "rb") as f_in:
            # We cant get the real name for the file inside the gzip archive so
            # we assign a random string as name for the file.
            fname = str(randomString())
            newfile = str(workdir) + "/" + fname
            with open(newfile, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
                newext = magic.detect_from_filename(newfile).mime_type
                newfilepath = Path(newfile)
                # Checking MIME type of the file and change the
                # name of the file to right ext.
                if "application/x-tar" in str(newext):
                    newarchive = newfilepath.rename(
                                newfilepath.with_suffix(".tar"))
                    logger.info(f"Unpacked {newfile}.tar from {filename}")
                elif "application/zip" in str(newext):
                    newarchive = newfilepath.rename(
                                newfilepath.with_suffix(".zip"))
                    logger.info(f"Unpacked {newfile}.zip from {filename}")
                elif "application/gzip" in str(newext):
                    newarchive = newfilepath.rename(
                                newfilepath.with_suffix(".gz"))
                    logger.info(f"Unpacked {newfile}.gz from {filename}")
                else:
                    logger.warning(
                        f"""Something is off with the MIME-information
                                   ({newext}), but don't worry! We will make a
                                   try to unpack {newfile} anyway!"""
                    )
                    return newfilepath
                result = str(newarchive)
    elif "application/x-tar" in guessfile:
        tar = tarfile.open(filename, "r")
        tar.extractall(path=workdir)
        filelist = tar.getnames()
        if filelist:
            result = str(workdir) + "/" + str(filelist[0])
    elif "text/plain" in guessfile:
        with open(filename, "r") as fin:
            logger.info(f"Output of {filename} :\n {fin.read()}")
        result = None
    else:
        logger.warning(f" {filename} is unknown format! Script will exit now")
        result = None
    return result


def main():
    archive_file = args["archive"]
    while archive_file is not None:
        result = unpacking(archive_file)
        archive_file = result


if __name__ == "__main__":
    main()
