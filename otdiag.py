# -*- coding: utf-8 -*-

from __future__ import division

from builtins import object
from splunk.util import cmp
from builtins import range
from builtins import map
from builtins import filter
from builtins import object

import os
import subprocess
import sys
import platform
import string
import shutil
import tarfile
import stat
import logging
import splunk.clilib.cli_common

try:
    import splunk.clilib.log_handlers
except:
    splunk.clilib.log_handlers = None
import datetime
import time  # two time modules, zzz
import optparse
import fnmatch
import re
import glob
import socket
import traceback

if sys.version_info >= (3, 0):
    from io import StringIO
    from io import BytesIO
else:  # py2 has io.StringIO but it behaves differently, we want the classic version:
    from StringIO import StringIO
import tempfile
from future.moves.urllib import request as urllib_request
from future.moves.urllib import error as urllib_error
from future.moves.urllib import parse as urllib_parse
import threading
import functools
import errno
import itertools
import base64
import getpass
import json

# ssl import can fail when diag is not run with proper splunk env
'''try:
    import sslssl
except:
    ssl = object()
    ssl.SSLError = None'''
# and some digging into extension modules to enforce forward-compatibility
import inspect

SPLUNK_HOME = os.environ['SPLUNK_HOME']
SPLUNK_ETC = os.environ.get('SPLUNK_ETC')
RESULTS_LOC = os.path.join(SPLUNK_HOME, 'var', 'run', 'splunk', 'diag-temp')
MSINFO_FILE = 'msinfo-sum.txt'
SYSINFO_FILE = 'systeminfo.txt'
COMPOSITE_XML = os.path.join(SPLUNK_HOME, 'var', 'run', 'splunk', 'composite.xml')
SSL_CONFIG_STANZA = 'sslConfig'

KNOWN_COMPONENTS = ("index_files",
                    "index_listing",
                    "dispatch",
                    "etc",
                    "log",
                    "searchpeers",
                    "consensus",
                    "conf_replication_summary",
                    "suppression_listing",
                    "rest",
                    "kvstore",
                    "file_validate",
                    )

system_info = None  # systeminfo.txt file obj; if you want to use reporting
# functions externally, set this as desired.


# the general logger; gets to diag.log & screen
logger = logging
# only goes to diag.log (or a temp file on failure), used for adding additional
# info that isn't helpful onscreen
auxlogger = logging


# These two are initialized to the 'logging' module, so there's some kind of log
# behavior no matter what; but they're really set up in logging_horrorshow()

# =====================================
# === ВСЯКАЯ ВРЕМЕННАЯ ШНЯГА _tmpsh ===
# =====================================
app_info_dict = {}

def logging_horrorshow():
    disable_clilib_logger()
    buffer_obj = setup_buffer_logger()
    setup_main_logger()
    return buffer_obj

def app_ext_names():
    "returns the list of apps with diag extensions configured"
    return list(app_info_dict.keys())

def ot_failure():
    print("4toto poshlo ne tak")

def app_components():
    "returns a tuple of the component names for apps with diag extensions"
    return tuple(app.component_name for app in app_info_dict.values())

def local_getopt(file_options, cmd_argv=sys.argv):
    "Implement cmdline flag parsing using optparse"

    def set_components(option, opt_str, value, parser):
        "Override any existing set of enabled components with the provided string"
        if not value:
            raise optparse.OptionValueError("--collect argument missing")

        components = value.split(",")
        all_components = set(KNOWN_COMPONENTS).union(set(app_components()))
        if 'all' in components:
            parser.values.components = all_components
        else:
            req_components = set(components)
            unknown_components = req_components.difference(all_components)
            if unknown_components:
                as_string = ",".join(unknown_components)
                raise optparse.OptionValueError("Unknown components requested: " + as_string)
            parser.values.components = req_components

    def enable_component(option, opt_str, value, parser):
        "Add one component to the enabled set of components"
        component = value
        if component not in (KNOWN_COMPONENTS + app_components()):
            raise optparse.OptionValueError("Unknown component requested: " + component)
        elif component in parser.values.components:
            logger.warn("Requested component '%s' was already enabled.  No action taken." % component)
        else:
            parser.values.components.add(component)

    def disable_component(option, opt_str, value, parser):
        "Remove one component from the enabled set of components"
        component = value
        if component not in (KNOWN_COMPONENTS + app_components()):
            raise optparse.OptionValueError("Unknown component requested: " + component)
        elif component not in parser.values.components:
            logger.warn("Requested component '%s' was already disabled.  No action taken." % component)
        else:
            parser.values.components.remove(component)

    def _parse_size_string(value, setting_name):
        "accept sizes like 10kb or 2GB, returns value in bytes"
        sizemap = {"b":      1,
                   "kb": 2**10,
                   "mb": 2**20,
                   "gb": 2**30,
                   "tb": 2**40,
                   "pb": 2**50,   # perhaps being too completeist here
        }
        numbers = re.match('^\d+', value)
        if not numbers:
            msg = "Could not find integer in %s target '%s'" % (setting_name, value)
            raise optparse.OptionValueError(msg)
        base_number = int(numbers.group(0))
        rest = value[numbers.end():]

        if not rest:
            # no indication means kilobytes (history)
            rest = "kb"

        if not rest.lower() in sizemap:
            msg = "Could not understand '%s' as a size denotation" % rest
            raise optparse.OptionValueError(msg)
        number = base_number * sizemap[rest.lower()]
        return number

    def set_log_size_limit(option, opt_str, value, parser):
        "sets limit on files for var/log dir"
        number = _parse_size_string(value, "--log-filesize-limit")
        parser.values.log_filesize_limit = number

    def set_etc_size_limit(option, opt_str, value, parser):
        "sets limit on files for etc dir"
        number = _parse_size_string(value, "--etc-filesize-limit")
        parser.values.etc_filesize_limit = number

    # handle arguments
    parser = optparse.OptionParser(usage="Usage: splunk diag [options]")
    parser.prog = "diag"

    # yes, a negative option. I'm a bastard
    parser.add_option("--nologin", action="store_true",
                      help="override any use of REST logins by components/apps")

    parser.add_option("--auth-on-stdin", action="store_true",
                      help="Indicates that a local splunk auth key will be provided on the first line of stdin")

    component_group = optparse.OptionGroup(parser, "Component Selection",
                      "These switches select which categories of information "
                      "should be collected.  The current components available "
                      "are: " + ", ".join(KNOWN_COMPONENTS + app_components()))

    parser.add_option("--exclude", action="append",
                      dest="exclude_list", metavar="pattern",
                      help="glob-style file pattern to exclude (repeatable)")

    component_group.add_option("--collect", action="callback", callback=set_components,
                      nargs=1, type="string", metavar="list",
                      help="Declare an arbitrary set of components to gather, as a comma-separated list, overriding any prior choices")
    component_group.add_option("--enable", action="callback", callback=enable_component,
                      nargs=1, type="string", metavar="component_name",
                      help="Add a component to the work list")
    component_group.add_option("--disable", action="callback", callback=disable_component,
                      nargs=1, type="string", metavar="component_name",
                      help="Remove a component from the work list")

    parser.add_option("--uri",
                      dest="uri", metavar="url",
                      help="url of a management port of a remote splunk install from which to collect a diag.")

    parser.add_option_group(component_group)

    detail_group = optparse.OptionGroup(parser, "Level of Detail",
                      "These switches cause diag to gather data categories "
                      "with lesser or greater thoroughness.")

    detail_group.add_option("--include-lookups", action="store_true",
                      help="Include lookup files in the etc component [default: do not gather]")

    detail_group.add_option("--all-dumps", type="string",
                      dest="all_dumps", metavar="bool",
                      help="get every crash .dmp file, opposed to default of a more useful subset")
    detail_group.add_option("--index-files", default="manifests", metavar="level",
                      help="Index data file gathering level: manifests, or full (meaning manifests + metadata files) [default: %default]")
    detail_group.add_option("--index-listing", default="light", metavar="level",
                      help="Index directory listing level: light (hot buckets only), or full (meaning all index buckets) [default: %default]")

    etc_filesize_default="10MB"
    detail_group.add_option("--etc-filesize-limit", type="string",
                      default=_parse_size_string(etc_filesize_default, ""), action="callback",
                      callback=set_etc_size_limit, metavar="size",
                      help="do not gather files in $SPLUNK_HOME/etc larger than this. (accepts values like 5b, 20MB, 2GB, if no units assumes kb), 0 disables this filter [default: %s]" % etc_filesize_default)
    detail_group.add_option("--log-age", default="60", type="int", metavar="days",
                      help="log age to gather: log files over this many days old are not included, 0 disables this filter [default: %default]")

    log_filesize_default="1GB"
    detail_group.add_option("--log-filesize-limit", type="string",
                      default=_parse_size_string(log_filesize_default, ""), action="callback",
                      callback=set_log_size_limit, metavar="size",
                      help="fully gather files in $SPLUNK_HOME/var/log smaller than this size.  For log files larger than this size, gather only this many bytes from the end of the file (capture truncated trailing bytes). [default: %s]" % log_filesize_default)

    parser.add_option_group(detail_group)

    filter_group = optparse.OptionGroup(parser, "Data Filtering",
                      "These switches cause diag to redact or hide data from the output diag.")

    filter_group.add_option("--filter-searchstrings", action="store_true", dest="filtersearches",
                      default=True,
                      help="Attempt to redact search terms from audit.log & remote_searches.log that may be private or personally identifying")

    filter_group.add_option("--no-filter-searchstrings", action="store_false", dest="filtersearches",
                      help="Do not modify audit.log & remote_searches.log")

    parser.add_option_group(filter_group)

    output_group = optparse.OptionGroup(parser, "Output",
                      "These control how diag writes out the result.")

    output_group.add_option("--stdout", action="store_true", dest="stdout",
                      help="Write an uncompressed tar to standard out.  Implies no progress messages.")

    output_group.add_option("--diag-name", "--basename", metavar="name", dest="diagname",
                      help="Override diag's default behavior of autoselecting its name, use this name instead.")

    output_group.add_option("--statusfile", metavar="filename", dest="statusfile",
                      help="Write progress messages to a file specified by the given path. Useful with --stdout.")

    output_group.add_option("--debug", action="store_true", dest="debug",
                      help="Print debug output")

    parser.add_option_group(output_group)


    upload_group = optparse.OptionGroup(parser, "Upload",
                     "Flags to control uploading files\n Ex: splunk diag --upload")

    upload_group.add_option("--upload", action="store_true", dest="upload",
                      help="Generate a diag and upload the result to splunk.com")

    upload_group.add_option("--upload-file", metavar="filename",
                      dest="upload_file",
                      help="Instead of generating a diag, just upload a file")

    upload_group.add_option("--case-number", metavar="case-number",
                      type='int', dest="case_number",
                      help="Case number to attach to, e.g. 200500")

    upload_group.add_option("--upload-user", dest="upload_user",
                      help="splunk.com username to use for uploading")

    upload_group.add_option("--upload-description", dest="upload_description",
                      help="description of file upload for Splunk support")

    upload_group.add_option("--firstchunk", type="int", metavar="chunk-number",
                      help="For resuming upload of a multi-part upload; select the first chunk to send")

    parser.add_option_group(upload_group)

    class Extension_Callback(object):
        """proxy object to permit extension to communicate other facts back.
           All we have so far is a will_need_rest() method"""
        def will_need_rest(self):
            _will_need_rest()

    # add any further parser config stuff for app extensions
    class Parser_Proxy(object):
        "proxy object for option parser to handle namespacing app options"
        def __init__(self, app_info, parser):
            self.app_info = app_info
            self.parser = parser
            self.optiongroup = None

        def add_option(self, *flags, **kwargs):
            if  ((len(flags) != 1) or (not flags[0].startswith('--'))):
                raise NotImplementedError("Diag extensions only support long opts (--foo -> --app.foo) for apps")

            # create an option group for the app, since it has at least one
            # flag. (visual help treatment)
            if not self.optiongroup:
                self.optiongroup = optparse.OptionGroup(self.parser,
                                                        "%s options" % self.app_info.component_name)

            #namespace and pass along the option add
            option_str = flags[0]
            proxied_flag = '--%s:%s' % (self.app_info.app_name, option_str.lstrip('-'))
            if 'dest' in  kwargs:
                if not 'metavar' in kwargs:
                    kwargs['metavar'] = kwargs['dest']
                kwargs['dest']  = "%s.%s" % (self.app_info.app_name, kwargs['dest'])
            self.optiongroup.add_option(proxied_flag, **kwargs)

        def _complete(self):
            "If any options were added, add the group to the parser"
            if self.optiongroup:
                self.parser.add_option_group(self.optiongroup)

    # setup hook for app to provide its own options
    for diag_ext_app in app_ext_names():
        app_info = get_app_ext_info(diag_ext_app)
        logger.debug("app_info: %s" % app_info)
        # set up a proxy object to namespace app options
        parser_proxy = Parser_Proxy(app_info, parser)
        callback = Extension_Callback()
        try:
            app_info.module_obj.setup(parser=parser_proxy,
                                      app_dir=app_info.app_dir,
                                      callback=callback)
        except Exception as e:
            # for any kind of failure, log an error, store the exception in
            # the app_info object, and turn off collection for the app later.
            exception_text = traceback.format_exc()
            msg = "Diag extensions: App %s threw an exception during setup(). No Extension collection will happen for this app, exception text will be stored in the diag at %s."
            output_path = os.path.join("app_ext", diag_ext_app, "setup_failed.output")
            logger.error(msg, diag_ext_app, output_path)

            invalidate_app_ext(diag_ext_app)
            store_app_exception(diag_ext_app, exception_text)

        parser_proxy._complete()

    # diag-collect every category, except REST, by default
    # no REST for now  because there are too many question marks about reliability
    default_components = set(KNOWN_COMPONENTS) | set(app_components())
    default_components.remove('rest')
    parser.set_defaults(components=default_components)

    # override above defaults with any from the server.conf file
    parser.set_defaults(**file_options)

    options, args =  parser.parse_args(cmd_argv)

    if options.index_files not in ('manifests', 'manifest', 'full'):
        parser.error("wrong value for index-files: '%s'" % options.index_files)

    if options.index_listing not in ('light', 'full'):
        parser.error("wrong value for index-listing: '%s'" % options.index_listing)

    if options.upload and options.upload_file:
        parser.error("You cannot use --upload and --upload-file in one command")

    if options.upload_file:
        try:
            f = open(options.upload_file)
            f.close()
        except (IOError, OSError) as e:
            parser.error("Cannot open file %s for reading: %s" %
                         (options.upload_file, e.strerror))
    elif options.upload_file == "":
        parser.error("Empty-string is not a valid argument for --upload-file")

    if not (options.upload or options.upload_file) and (
               options.upload_user or
               options.case_number or
               options.upload_description):
        parser.error("Upload values provided, but no upload mode chosen: you need --upload or --upload-file")

    return options, args

# ========================================================
# === TEMLATE FUNCTION FOR ADDING CREATED FILE TO DIAG ===
# ========================================================

'''def copy_something_to_diag():
    add_file_to_diag(file_path, diag_path)
    dir_to_add = os.path.join("opt, "dir", "to", "add")
    add_file_to_diag(src_file, os.path.join("dispatch", job, f))'''

# ===============================================================================
# === ВРЕМЕННО ВКЛЮЧЕННЫЕ ФУНКЦИИ ДЛЯ ТОГО, ЧТОБЫ РАБТАЛО СОЗДАНИЕ TAR АРХИВА ===
# ===============================================================================

excluded_filelist = []


def reset_excluded_filelist():
    "Wipe it, just in case we ever make this module persistent"
    global excluded_filelist
    excluded_filelist = []


def build_filename_filters(globs):
    if not globs:
        return []
    glob_to_re = lambda s: re.compile(fnmatch.translate(s))
    return list(map(glob_to_re, globs))


def set_storage_filters(filter_list):
    global _storage_filters
    _storage_filters = filter_list


# ====================================================================================================================
# === СОЗДАЕМ ЭКЗЕМПЛЯР КЛАССА DirectTar - ЭТО, ПО СУТИ БУДУЩИЙ АРХИВ С РАЗЛИЧНЫМИ МЕТОДАМИ ДОДАВЛЕНИЯ В НЕГО ИНФЫ ===
# ====================================================================================================================

storage = None


def set_storage(style):
    print("otdone1: with creating DirectTar")
    global storage
    if style == "directory":
        storage = OutputDir()
    elif style == "tar":
        print("otdone2: with creating DirectTar")
        storage = DirectTar()
    else:
        raise "WTF"


##################
# Scaffolding for accepting data to add to the diag
# ==========================================================================
# === ПО СУТИ БУДУЩИЙ АРХИВ С РАЗЛИЧНЫМИ МЕТОДАМИ ДОДАВЛЕНИЯ В НЕГО ИНФЫ ===
# ==========================================================================
class DirectTar(object):
    def __init__(self, compressed=True):
        self.compressed = compressed
        self.stored_dirs = set()
        # stores set of directories so we can force parent dirs to
        # exist in the tarball

    def setup(self, options):
        if options.stdout:
            # start off without compression -- http server code compresses
            sys_stdout = sys.stdout
            if sys.version_info >= (3, 0):
                sys_stdout = sys.stdout.buffer
                # The underlying binary buffer (a BufferedIOBase instance)
            self.tarfile = tarfile.open(get_tar_pathname(compressed=False), 'w|',
                                        fileobj=sys_stdout)
        elif not self.compressed:
            # This branch is not live -- should it ever be?
            self.tarfile = tarfile.open(get_tar_pathname(compressed=False), 'w')
        elif False:
            # If we want to do streaming compressed output.. this crap is needed
            # BEGIN MONKEY PATCHING!!!!
            def lower_compression_init_write_gz(self):
                desired_compression = 6
                self.cmp = self.zlib.compressobj(6, self.zlib.DEFLATED,
                                                 -self.zlib.MAX_WBITS, self.zlib.DEF_MEM_LEVEL, 0)
                timestamp = tarfile.struct.pack("<L", int(time.time()))
                self._Stream__write("\037\213\010\010%s\002\377" % timestamp)
                if isinstance(self.name, unicode):
                    self.name = self.name.encode("iso-8859-1", "replace")
                if self.name.endswith(".gz"):
                    self.name = self.name[:-3]
                self._Stream__write(self.name + tarfile.NUL)

            tarfile._Stream._init_write_gz = lower_compression_init_write_gz
            # END MONKEY PATCHING!!!!
            self.tarfile = tarfile.open(get_tar_pathname(), 'w|gz')
        else:
            # default case
            self.tarfile = tarfile.open(get_tar_pathname(), 'w:gz', compresslevel=6)
        self._add_empty_named_dir(get_diag_name())

    def _add_empty_named_dir(self, diag_path):
        "Add a directory of a particular name, for tar completeness"
        logger.debug("_add_empty_named_dir(%s)" % diag_path)
        tinfo = tarfile.TarInfo(diag_path)
        tinfo.type = tarfile.DIRTYPE
        tinfo.mtime = time.time()
        tinfo.mode = 0o755  # dir needs x
        self.tarfile.addfile(tinfo)
        self.stored_dirs.add(diag_path)

    def _add_unseen_parents(self, file_path, diag_path):
        """Add all parents of a dir/file of a particular name,
           that are not already in the tar"""
        logger.debug("_add_unseen_parents(%s, %s)" % (file_path, diag_path))
        parents = []
        src_dir = file_path
        tgt_dir = diag_path
        # we are looking for two goals here:
        # 1 - create an entry in the tar so we get sane behavior on unpack
        # 2 - if the source dir is from a file inside splunk_home, the dir
        #     entries should match the permissions, timestamps,
        if file_path.startswith(SPLUNK_HOME):
            while True:
                logger.debug("_add_unseen_parents() -> tgt_dir=%s src_dir=%s", tgt_dir, src_dir)
                prior_tgt_dir = tgt_dir
                prior_src_dir = src_dir
                tgt_dir = os.path.dirname(tgt_dir)
                src_dir = os.path.dirname(src_dir)
                if not tgt_dir or tgt_dir == "/" or tgt_dir == get_diag_name() or tgt_dir == prior_tgt_dir:
                    break
                if not src_dir or src_dir in ("/", "\\") or src_dir == prior_src_dir:
                    # This is here because this case almost certainly represents
                    # a logic bug (one existed at some point)
                    raise Exception("Wtf.  " +
                                    "You copied a shorter source dir into a longer target dir? " +
                                    "Does this make sense in some universe? " +
                                    "args were: file_path=%s diag_path=%s" % (file_path, diag_path))
                if not tgt_dir in self.stored_dirs:
                    parents.append((src_dir, tgt_dir))
            if not parents:
                return
            logger.debug("_add_unseen_parents --> parents:(%s)" % parents)
            parents.reverse()  # smallest first
            for src_dir, tgt_dir in parents:
                if os.path.islink(src_dir) or not os.path.isdir(src_dir):
                    # We can't add a non-directory as a parent of a directory
                    # or file, extracting will fail or be unsafe.
                    # it should be a symlink
                    if os.path.islink(src_dir):
                        # XXX change to auxlogger
                        msg = "Encountered symlink: %s -> %s; storing as if plain directory. Found adding parent dirs of %s."
                        logging.warn(msg, src_dir, os.readlink(src_dir), file_path)
                        # for symlinks, we want to get the perm data from the
                        # target, since owner/perm/etc data on a symlink has no
                        # meaning.
                        symlink_target = os.path.realpath(src_dir)
                        if not os.path.exists(symlink_target):
                            logging.error("Link target does not exist(!!)")
                            tarinfo = self.tarfile.gettarinfo(src_dir, arcname=tgt_dir)
                        else:
                            tarinfo = self.tarfile.gettarinfo(symlink_target, arcname=tgt_dir)
                    else:
                        # This should not be a possible branch, but paranoia
                        msg = "Encountered unexpected filetype: %s stat: %s storing as if directory. Found adding parent dirs of %s."
                        logging.warn(msg, src_dir, os.stat(src_dir), file_path)
                        tarinfo = self.tarfile.gettarinfo(src_dir, arcname=tgt_dir)
                    # Either way, pretend it's a directory
                    tarinfo.type = tarfile.DIRTYPE
                    self.tarfile.addfile(tarinfo)
                else:
                    self.tarfile.add(src_dir, arcname=tgt_dir, recursive=False)
                self.stored_dirs.add(tgt_dir)
        else:
            # we're adding a file from outside SPLUNK_HOME.  Probably a temp
            # file.  TODO -- should we enforce something here?
            while True:
                logger.debug("_add_unseen_parents() outside SPLUNK_HOME -> tgt_dir=%s", tgt_dir)
                prior_tgt_dir = tgt_dir
                tgt_dir = os.path.dirname(tgt_dir)
                if not tgt_dir or tgt_dir == "/" or tgt_dir == get_diag_name() or tgt_dir == prior_tgt_dir:
                    break
                if not tgt_dir in self.stored_dirs:
                    parents.append(tgt_dir)
            if not parents:
                return
            logger.debug("_add_unseen_parents --> parents:(%s)" % parents)
            parents.reverse()  # smallest first
            for dir in parents:
                self._add_empty_named_dir(tgt_dir)

    '''def complete(self, *ignore):
        self.tarfile.close()'''
    def complete(self):
        self.tarfile.close()

    def add(self, file_path, diag_path):
        logger.debug("add(%s)" % file_path)
        if diag_path in self.stored_dirs:
            # nothing to do
            return
        try:
            self._add_unseen_parents(file_path, diag_path)
            if os.path.isdir(file_path):
                self.stored_dirs.add(diag_path)
            self.tarfile.add(file_path, diag_path, recursive=False)
        except IOError as e:
            # report fail, but continue along
            err_msg = "Error adding file '%s' to diag, failed with error '%s', continuing..."
            logger.warn(err_msg % (file_path, e))
            pass

    def add_fileobj(self, fileobj, diag_path):
        logger.debug("add_fileobj(%s)" % diag_path)
        if os.name == "nt":
            # Tar only supports /; we handle changing to / here because:
            # 1 - dir implementation would want \
            # 2 - tarfile.add already seamlessly handles this for add and add_dir
            diag_path = diag_path.replace("\\", "/")

        # tarfile imposes the need to handle stringio files completely
        # differently from real files :-(
        if hasattr(fileobj, 'is_stringio') and fileobj.is_stringio:
            tinfo = tarfile.TarInfo(diag_path)
            tinfo.size = fileobj.size()
            tinfo.mtime = fileobj.mtime()
            self.tarfile.addfile(tinfo, fileobj=fileobj)
        else:
            # gettarinfo is very insistent that it finds out the name itself for a fileobj
            fileobj.name = diag_path
            tinfo = self.tarfile.gettarinfo(arcname=diag_path, fileobj=fileobj)
            self.tarfile.addfile(tinfo, fileobj=fileobj)

    def add_dir(self, dir_path, diag_path, ignore=None):
        logger.debug("add_dir(%s)" % dir_path)
        adder = functools.partial(add_file_to_diag, add_diag_name=False)
        collect_tree(dir_path, diag_path, adder, ignore=ignore)

    def add_string(self, s, diag_path):
        if os.name == "nt":
            # Tar only supports /; we handle changing to / here because:
            # 1 - dir implementation would want \
            # 2 - tarfile.add already seamlessly handles this for add and add_dir
            diag_path = diag_path.replace("\\", "/")
        tinfo = tarfile.TarInfo(diag_path)
        tinfo.size = len(s)
        tinfo.mtime = time.time()
        # tarfile requires a file for adding.. sigh
        if sys.version_info >= (3, 0):
            if isinstance(s, str):
                s = s.encode()
            s_file = BytesIO(s)
        else:
            s_file = StringIO(s)
        self.tarfile.addfile(tinfo, fileobj=s_file)
        s_file.close()

    def add_fake_file(self, file_path, diag_path):
        logger.debug("add_fake_file(%s) %s" % (file_path, diag_path))

        tinfo = tarfile.TarInfo(name=diag_path)

        statres = os.lstat(file_path)
        tinfo.mode = statres.st_mode
        tinfo.uid = statres.st_uid
        tinfo.gid = statres.st_gid
        tinfo.mtime = statres.st_mtime
        tinfo.size = 0
        tinfo.type = tarfile.REGTYPE
        self.tarfile.addfile(tinfo)


# ==========================
# === ПОЛУЧАЕМ ИМЯ ДИАГА ===
# ==========================

def get_diag_date_str():
    return datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')


def format_diag_name(host_part):
    date_str = get_diag_date_str()
    return "diag-%s-%s" % (host_part, date_str)


diag_name = None


def get_splunkinstance_name():
    # Octavio says the hostname is preferred to machine-user, and that
    # multiple-splunks-per-host is now rare, so just use hostname
    return socket.gethostname()


def get_diag_name(base=None):
    """Construct the diag's name,
       used both for paths inside and for the containing tarname"""
    # hack to create 'static' value
    global diag_name
    if not diag_name:
        if not base:
            base = get_splunkinstance_name()
        diag_name = format_diag_name(base)
        # logger.info('Selected diag name of: ' + diag_name)
    return diag_name


def format_tar_name(basename, compressed=True):
    """ Construct a filename for the diag """
    extension = ".tar"
    if compressed:
        extension += ".gz"
    return basename + extension


def get_tar_pathname(filename=None, compressed=True):
    """ Construct the output pathname for the diag """
    if not filename:
        filename = get_diag_name()
    tar_filename = format_tar_name(filename)

    # TODO: give user control over output dir/path entirely
    return (os.path.join(SPLUNK_HOME, tar_filename))


# ======================================
# === ДОБАВИТЬ ФАЙЛ К БОЛШОМУ DIAG'У ===
# ======================================

# These are requests -- exclusion filtering happens transparently in here.

_storage_filters = []


def set_storage_filters(filter_list):
    global _storage_filters
    _storage_filters = filter_list


def path_unwanted(filename):
    for regex in _storage_filters:
        if regex.match(filename):
            return True
    return False


def wants_filter(diag_path):
    logger.debug("wants_filter(%s)", diag_path)
    return bool(get_filter(diag_path))


def add_excluded_file(path):
    """tell the file exclude tracker that a diag-relative path has not been included
       even though the component is enabled"""
    logger.debug("add_excluded_file(%s)" % path)
    reason = "EXCLUDE"
    excluded_filelist.append((reason, path))


def add_file_to_diag(file_path, diag_path, add_diag_name=True):
    """Add a single file: file_path points to file on disk,
                          diag_path says where to store in the tar"""
    # logger.debug("add_file_to_diag(%s, %s)" % (file_path, diag_path))

    # all files live in the diag prefix
    if add_diag_name:
        diag_path = os.path.join(get_diag_name(), diag_path)

    # Далее что-то про исключение файлов из Диага. Возможно, работает через параметры утилиты.
    '''if path_unwanted(diag_path):
        add_excluded_file(diag_path)
        return

    if wants_filter(diag_path):
        add_filtered_file_to_diag(file_path, diag_path)
        return'''

    # We don't put in block devices, sockets, etc in the tar.
    # No booby-traps

    # Исключить сбор специальных файлов
    '''special_type = is_special_file(file_path)
    if special_type:
        add_fake_special_file_to_diag(file_path, diag_path, special_type)
        return'''

    storage.add(file_path, diag_path)


# ==========================================================
# === УТИЛИТЫ КОМАНДНОЙ СТРОКИ, НАПРИМЕР, СБОР ОКРУЖЕНИЯ ===
# ==========================================================

def networkConfig():
    """ Network configuration  """

    # system_info.write('\n\n********** Network Config  **********\n\n')
    # we call different utilities for windows and "unix".
    if os.name == "posix":
        # if running as a non-root user, you may not have ifconfig in your path.
        # we'll attempt to guess where it is, and if we can't find it, just
        # assume that it is somewhere in your path.
        ifconfig_exe = '/sbin/ifconfig'
        if not os.path.exists(ifconfig_exe):
            ifconfig_exe = 'ifconfig'
        exit_code, output = simplerunner([ifconfig_exe, "-a"], timeout=3)
    else:
        exit_code, output = simplerunner(["ipconfig", "/all"], timeout=3)
    if output:
        system_info.write(output)
        print("network output here")
        # print(output)


# === main() ===
'''def create_diag():
    networkConfig()'''


def create_diag():
    """ According to the options, create a diag """
    '''reset_excluded_filelist()
    filter_list = build_filename_filters(options.exclude_list)
    set_storage_filters(filter_list)

    if not options.stdout:
        # don't "clean up" in --stdout mode, or -uri localhost fails bizarrely
        if os.path.exists(get_tar_pathname()):
            os.unlink(get_tar_pathname())
    '''
    # initialize whatever is needed for the storage type
    #options = {}
    file_options = {}
    '''if not '--uri' in "".join(sys.argv):
        file_options = read_config(app_infos=diagconf_app_infos)'''

    #logger.debug("app_modules: %s" % app_ext_names())
    options, args = local_getopt(file_options)

    storage.setup(options)
    '''
    # make sure it's a supported os.
    if not os.name in ("posix", "nt"):
        logger.error("FAIL: Unsupported OS (%s)." % os.name)
        write_logger_buf_on_fail(log_buffer)
        sys.exit(1)

    logger.info("Starting splunk diag...")

    setup_filters(options)

    # do rest first for now, simply to force interactive work to occur first
    if not 'rest' in options.components:
        logger.info("Skipping REST endpoint gathering...")
    else:
        gather_rest_content(options)'''

    sysinfo_filename = None

    try:
        try:
            global system_info
            system_info = tempfile.NamedTemporaryFile(prefix="splunk_sysinfo", mode="w+", delete=False)
            sysinfo_filename = system_info.name
        except IOError:
            # logger.error("Exiting: Cannot create system info file.  Permissions may be wrong.")
            # write_logger_buf_on_fail(log_buffer)
            sys.exit(1)

        # logger.info("Determining diag-launching user...")
        # who is running me?
        '''systemUsername()

        # Log facts about SPLUNK_HOME & SPLUNK_ETC
        text = get_env_info()
        system_info.write(text)

        logger.info("Getting version info...")
        #get the splunk version
        splunkVersion()

        logger.info("Getting system version info...")
        #uname
        systemUname()

        # splunk valiate files
        if 'file_validate' in options.components:
            logger.info("Getting file integrity info...")
            output = get_file_validation()
            system_info.write(output)

        logger.info("Getting network interface config info...")'''
        # ifconfig
        networkConfig()

        '''logger.info("Getting splunk processes info...")
        text = get_process_listing()
        system_info.write(text)

        logger.info("Getting netstat output...")
        #netstat
        networkStat()

        logger.info("Getting info about memory, ulimits, cpu (on windows this takes a while)...")
        #ulimit
        systemResources()

        logger.info("Getting etc/auth filenames...")
        get_listing(os.path.join(get_splunk_etc(), 'auth'), 'auth')

        logger.info("Getting Sinkhole filenames...")
        get_listing(os.path.join(SPLUNK_HOME, 'var', 'spool', 'splunk'), 'sinkhole')

        desc = 'search peer bundles'
        if 'searchpeers' in options.components:
            logger.info('Getting %s listings...' % desc)
            src = os.path.join(SPLUNK_HOME, 'var', 'run', 'searchpeers')
            get_listing(src, desc)
        else:
            logger.info('Skipping %s listings...' % desc)

        desc = 'conf replication summary'
        if 'conf_replication_summary' in options.components:
            logger.info('Getting %s listings...' % desc)
            src = os.path.join(SPLUNK_HOME, 'var', 'run', 'splunk', 'snapshot')
            get_listing(src, desc)
        else:
            logger.info('Skipping %s listings...' % desc)

        desc = 'suppression files'
        if 'suppression_listing' in options.components:
            logger.info('Getting %s listings...' % desc)
            src = os.path.join(SPLUNK_HOME, 'var', 'run', 'splunk', 'scheduler', 'suppression')
            get_listing(src, desc)
        else:
            logger.info('Skipping %s listings...' % desc)

        if 'kvstore' in options.components:
            kvStoreListing()
        else:
            logger.info("Skipping KV Store listings...")

        if 'index_listing' in options.components:
            #ls
            logger.info("Getting index listings...")
            splunkDBListing(options)
        else:
            logger.info("Skipping index listings...")
            '''
    # добавляем файл с системным окружением в diag
    finally:
        system_info.close()

    try:
        add_file_to_diag(sysinfo_filename, SYSINFO_FILE)
        print(sysinfo_filename, SYSINFO_FILE)
    finally:
        os.unlink(sysinfo_filename)

    # === TEMPLATE FOR ADDING FILE TO DIAG ===

    file_to_add = "/opt/file_to_add"
    filename_in_diag = "added_file"
    try:
        add_file_to_diag(file_to_add, filename_in_diag)
        print(file_to_add, filename_in_diag)
    finally:
        os.unlink(file_to_add)
    # ==================================================


    '''
    if not 'etc' in options.components:
        logger.info("Skippping Splunk configuration files...")
    else:
        #copy etc and log into results too
        logger.info("Copying Splunk configuration files...")
        copy_etc(options)

    if not 'log' in options.components:
        logger.info("Skipping Splunk log files...")
    else:
        logger.info("Copying Splunk log files...")
        copy_logs(options)

    if not 'index_files' in options.components:
        logger.info("Skipping index files...")
    else:
        # TODO: try to link these lines to the actual work more strongly
        if options.index_files == "full":
            logger.info("Copying index worddata, and bucket info files...")
        else:
            logger.info("Copying bucket info files...")
        copy_indexfiles(options.index_files)

    # TODO: combine next two blocks
    # There's no need to make this a component, it's a single file
    if not os.path.exists(COMPOSITE_XML):
        logger.warn("Unable to find composite.xml file, product has likely not been started.")
    else:
        try:
            add_file_to_diag(COMPOSITE_XML, os.path.basename(COMPOSITE_XML))
            #shutil.copy(COMPOSITE_XML, get_results_dir())
        except IOError as e:
            # windows sucks
            err_msg = "Error copying in composite.xml: '%s' continuing..."
            logger.warn(err_msg % e.strerror)

    client_serverclass_file = "serverclass.xml"
    client_serverclass_path = os.path.join(SPLUNK_HOME, "var", "run",
                                           client_serverclass_file)
    if os.path.exists(client_serverclass_path):
        try:
            logger.info("Adding deployment client info file 'serverclass.xml'.")
            add_file_to_diag(client_serverclass_path, client_serverclass_file)
        except IOError as e:
            # windows sucks
            err_msg = "Error copying in serverclass.xml: '%s' continuing..."
            logger.warn(err_msg % e.strerror)



    if not 'dispatch' in options.components:
        logger.info("Skipping Splunk dispatch files...")
    else:
        logger.info("Copying Splunk dispatch files...")
        copy_dispatch_dir()

    if not 'consensus' in options.components:
        logger.info("Skipping Splunk consensus files...")
    else:
        logger.info("Copying Splunk consensus files...")
        copy_raft_dir()

    # again.. so small...
    if os.name == "nt":
        logger.info("Copying windows input checkpoint files...")
        copy_win_checkpoints()
    copy_scripts()
    copy_manifests()
    copy_cachemanager_upload()

    gather_app_extensions(options)

    # write out all the files that have been skipped
    excl_filelist = get_excluded_filelist()
    add_string_to_diag(excluded_filelist_to_str(excl_filelist),
                       "excluded_filelist.txt")

    # Add any exception texts for apps that had an exception during setup()
    if app_setup_exceptions_dict:
        # non-empty
        logger.info("Adding app exception texts to diag....")
        for app_name, exception_text in app_setup_exceptions_dict.items():
            output_path = os.path.join("app_ext", app_name, "setup_failed.output")
            add_string_to_diag(exception_text, output_path)

    log_buffer.write("diag.log complete\n")
    # now add the log buffer for all output during diag run
    add_string_to_diag(log_buffer.getvalue(), "diag.log")'''

    #storage.complete(options, log_buffer)
    storage.complete()


# === main() ===

def main():
    set_storage("tar")
    hostname = socket.gethostname()
    print(hostname)
    tar_pathname = get_tar_pathname()
    print(tar_pathname)
    options = {}
    create_diag()

    # We want all logged messages to hit our custom in-memory StringIO buffer;
    # but only *SOME* messages to land on the terminal.
    #log_buffer = logging_horrorshow()

    '''# handle options

    extending_app_infos, diagconf_app_infos = discover_apps()
    prepared_app_modules = {}
    for app_info in extending_app_infos:
        try:
            import_app_ext(app_info) # modifies app_info
            prepared_app_modules[app_info.app_name] = app_info
        except:
            msg = "failure encountered initializing diag extensions for app %s..."
            logger.error(msg % app_info.app_name)
            logger.error(traceback.format_exc())
            logger.error("...proceeding")

    _store_prepared_app_info(prepared_app_modules)

    # hack.. if we're doing --uri, then we don't want to use our locally
    # configured conf file; proper solution is probably to parse arguments
    # first, and then handle file defaults after, I suppose, or to split arg
    # parsing into two phases.
    file_options = {}
    if not '--uri' in "".join(sys.argv):
        file_options = read_config(app_infos=diagconf_app_infos)

    logger.debug("app_modules: %s" % app_ext_names())
    options, args = local_getopt(file_options)

    if options.auth_on_stdin:
        token = sys.stdin.readline().strip()
        set_session_key(token)

    adjust_logging(options)
    if options.diagname:
        set_diag_name(options.diagname)

    if options.uri:
        remote_diag(options, log_buffer)
        return True # Done with success

    if options.statusfile:
        # this is typically used remotely; don't have another clear way of
        # knowing this at the moment.
        logger.info("Remote command line was: %s" % sys.argv)

    # messy, complete info on options no one wants to see...
    auxlogger.info("The full set of options was: %s" % options)
    auxlogger.info("The set of requested components was: %s" % sorted(list(options.components)))

    if not options.upload_file:
        # short version that's a bit more digestible
        logger.info("Collecting components: %s", ", ".join(sorted(list(options.components))))

        off_components = set(KNOWN_COMPONENTS).difference(set(options.components))
        logger.info("Skipping components: %s", ", ".join(sorted(list(off_components))))

    if options.upload or options.upload_file:
        sys.stdout.write("\n") # blank line, not logged
        if options.upload_file:
            if not upload_file(options.upload_file, 'splunkcom', options):
                #TODO: pass return value back through clilib
                sys.exit("Upload failed.")
            return True # --upload-file means no create_diag()

        else:
            # generate and upload a diag; just ensure they have the prereqs
            if not ensure_upload_options(options):
                #TODO: pass return value back through clilib
                sys.exit("\nCannot validate upload options, aborting...")
                #return False

    # Do the work, trying to ensure the temp dir gets cleaned even on failure'''

    '''try:
        # Obey options? Dump this configurability? TODO
        #set_storage("in_memory")
        #set_storage("directory")

        set_storage("tar")

        # if the rest component is used, or if an app declared it wanted to do
        # rest, then do logins and so on now.
        if 'rest' in options.components or rest_needed:
            prepare_local_rest_access(options)

        create_diag(options, log_buffer)
    except Exception as e:
        logger.error("Exception occurred while generating diag, we are deeply sorry.")
        logger.error(traceback.format_exc())
        # this next line requests a file to be logged, not sure of clearest order
        write_logger_buf_on_fail(log_buffer)
        logger.info("We will now try to clean out any temporary files...")
        clean_temp_files()
        os.unlink(get_tar_pathname())
        #TODO: pass return value back through clilib
        sys.exit(1)
        #return False

    '''
    # and for normal conclusion..
    '''try:
        #clean up the results dir
        logger.info("Cleaning up...")
        clean_temp_files()
    finally:
        if not options.statusfile: # TODO better way to know if run remotely
            logger.info("Splunk diagnosis file created: %s" % get_tar_pathname())

    if options.upload:
        logger.info("Will now upload result.")
        if upload_file(get_tar_pathname(), 'splunkcom', options):
            logger.info("You may wish to delete the diag file now.")
        else:
            logger.warn("Upload failed")
            if not chunk_complained:
                msg = "You may want to try uploading again with 'splunk diag --upload-file %s'"
                logger.info(msg, get_tar_pathname())
            #TODO: pass return value back through clilib
            sys.exit(1)
            #return False
    #return True'''


###################
# internal utility

def simplerunner(cmd, timeout, description=None, input=None):
    """ Using PopenRunner directly every time is tedious.  Do the typical stuff.

        cmd         :iterable of strings, eg argv
        timeout     :time to give the command to finish in seconds before it is
                     brutally killed
        description :string for logging about the command failing etc
        input       :string to stuff into stdin pipe the command
    """
    cmd_string = " ".join(cmd)
    if not description:
        description = cmd_string
    opener = functools.partial(subprocess.Popen, cmd,
                               stdout=subprocess.PIPE, shell=False)
    runner = PopenRunner(opener, description=description)
    exit_code = runner.runcmd(timeout=timeout, input=input)
    out = runner.stdout
    if not out:
        out = "The command '%s' was cancelled due to timeout=%s\n" % (cmd_string, timeout)
    return exit_code, out


class PopenRunner(object):
    """ Run a popen object (passed in as a partial) with a timeout

        opener = functools.partial(subprocess.Popen, cmd=["rm", "/etc/passwd"], arg=blah, another_arg=blee)
        runner = PopenRunner(opener, description="password destroyer")
        returncode = runner.runcmd(timeout=15)
        print(runner.stdout)
        print(runner.stderr)
    """

    def __init__(self, popen_f, description=None):
        """popen_f     :function that when called, returns a Popen object
           description :string for logging about the command failing etc
        """
        self.opener = popen_f
        self.description = description
        self.p_obj = None
        self.stdout = None
        self.stderr = None
        self.exception = None
        self.traceback = None

    def runcmd(self, timeout=10, input=None):
        """timeout     :time to give the command to finish in seconds
           input       :string to stuff into stdin pipe for command
        """

        def inthread_runner(input=input):
            try:
                self.p_obj = self.opener()
                if (input is not None) and sys.version_info >= (3, 0): input = input.encode()
                self.stdout, self.stderr = self.p_obj.communicate(input=input)
                if sys.version_info >= (3, 0):
                    self.stdout = self.stdout.decode()
                    if self.stderr is not None:
                        self.stderr = self.stderr.decode()
            except Exception as e:
                class fake_pobj(object):
                    pass

                if isinstance(e, OSError) and e.errno in (errno.ENOENT, errno.EPERM, errno.ENOEXEC, errno.EACCES):
                    # the program wasn't present, or permission denied; just report that.

                    # Aside: Popen finds out about the problem during a read call on the
                    # pipe, so the exception doesn't know the filename, and we
                    # don't here either.  Sad.

                    # we'll fib a bit and claim the errror desc is the output, for
                    # consumer purposes
                    self.stdout = str(e)
                    self.stderr = str(e)

                    # However, if they really want to know, the returncode will
                    # tell them the command did not run (this will be the return
                    # value of runcmd)
                    self.p_obj = fake_pobj()
                    self.p_obj.returncode = 127

                else:
                    # for everything else we want the stack to log
                    self.exception = e
                    self.traceback = traceback.format_exc()

                    self.p_obj = fake_pobj()
                    self.p_obj.returncode = -1

        thread = threading.Thread(target=inthread_runner)
        thread.start()
        thread.join(timeout)

        def log_action(action):
            if self.description:
                logger.warn("%s %s." % (action, self.description))
            else:
                logger.warn("%s stalled command." % (action,))

        if thread.is_alive():
            log_action("Terminating")
            if self.p_obj:  # the thread may not have set p_obj yet.
                self.p_obj.terminate()
            else:
                logger.warn("Unexpectedly tearing down a thread which never got started.")
            time.sleep(0.2)
            if thread.is_alive():
                log_action("Killing")
                if self.p_obj:  # the thread may not have set p_obj yet.
                    self.p_obj.kill()
                else:
                    logger.error("A python thread has completely stalled while attempting to run: %s" % (
                                self.description or "a command"))
                    logger.error("Abandoning that thread without cleanup, hoping for the best")
                    return 1
            thread.join()

        if self.exception:
            logger.error("Exception occurred during: %s" % (self.description or "a command"))
            logger.error(self.traceback)

        return self.p_obj.returncode


#######
# direct-run startup, normally splunk diag doesn't use this but
# splunk cmd python info_gather.py goes through here.

if __name__ == "__main__":
    main()
