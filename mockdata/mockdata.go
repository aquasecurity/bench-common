package mockdata

import (
	"io/ioutil"
	"os"
)

const TestData1 = `
---
path: '/home/xyz-111/blah'
searchTerm: 'blah'
searchType: 'contains'
`
const TestData2 = `
---
path: %v
searchTerm: '%v'
searchType: '%v'
`
const TestDataInTypes = `
---
path: %v
searchTerm: %v
searchType: %v
`

func CreateContentFile(filename string) error {

	content := []byte(`
The Go distribution includes a command, named "go", 
that automates the downloading, building, installation, 
and testing of Go packages and commands. 
This document talks about why we wrote a new command, what it is, what it's not, and how to use it.
Motivation
You might have seen early Go talks in which Rob Pike jokes that the idea for Go arose while waiting for a large Google server to compile. 
That really was the motivation for Go: to build a language that worked well for building the large software that Google writes and runs. 
It was clear from the start that such a language must provide a way to express dependencies between code libraries clearly, 
hence the package grouping and the explicit import blocks. It was also clear from the start that you might want arbitrary syntax for describing the code being imported; 
this is why import paths are string literals.
An explicit goal for Go from the beginning was to be able to build Go code using only the information found in the source itself, 
not needing to write a makefile or one of the many modern replacements for makefiles. 
If Go needed a configuration file to explain how to build your program, then Go would have failed.
At first, there was no Go compiler, and the initial development focused on building one and then building libraries for it. 
For expedience, we postponed the automation of building Go code by using make and writing makefiles. 
When compiling a single package involved multiple invocations of the Go compiler, we even used a program to write the makefiles for us. 
You can find it if you dig through the repository history.
The purpose of the new go command is our return to this ideal, 
that Go programs should compile without configuration or additional 
effort on the part of the developer beyond writing the necessary import statements.
Configuration versus convention
The way to achieve the simplicity of a configuration-free system is to establish conventions. 
The system works only to the extent that those conventions are followed. When we first launched Go, 
many people published packages that had to be installed in certain places, under certain names, 
using certain build tools, in order to be used. That's understandable: that's the way it works in most other languages. 
Over the last few years we consistently reminded people about the goinstall command (now replaced by go get) and its conventions: 
first, that the import path is derived in a known way from the URL of the source code; second, that the place to store the
sources in the local file system is derived in a known way from the import path; third, that each directory in a source tree
corresponds to a single package; and fourth, that the package is built using only information in the source code. Today,
the vast majority of packages follow these conventions. The Go ecosystem is simpler and more powerful as a result.
We received many requests to allow a makefile in a package directory to provide just a little extra configuration beyond what's 
in the source code. But that would have introduced new rules. Because we did not accede to such requests, we were able to write 
the go command and eliminate our use of make or any other build system.
It is important to understand that the go command is not a general build tool. It cannot be configured and 
it does not attempt to build anything but Go packages. These are important simplifying assumptions: 
they simplify not only the implementation but also, more important, the use of the tool itself.

`)
	return ioutil.WriteFile(filename, content, 0644)

}

var Mockfiles = []struct {
	File  string
	Perm  os.FileMode
	Ftype os.FileMode
}{
	{"test1", 0600, 0},
	{"test2", 0700, 0},
	{"test3", 0600, 0},
	{"test4", 0600, 0},
	{"test5", 0777, 0},
	{"test6", 0200, 0},
	{"test7", 040000755, 0},

	{"Imagetest1.jpg", 0200, 0},
	{"Imagetest2.jpg", 0200, 0},
	{"Imagetest3.jpg", 0200, 0},
	{"Imagetest4.jpg", 0200, 0},

	{"testdir1", 0600, os.ModeDir},
	{"testdir2", 0700, os.ModeDir},
	{"testdir3", 0600, os.ModeDir},
	{"testdir4", 0600, os.ModeDir},
	{"testdir5", 0777, os.ModeDir},
	{"testdir6", 0200, os.ModeDir},

	{"testlink1", 0600, os.ModeSymlink},
	{"testlink2", 0700, os.ModeSymlink},
	{"testlink3", 0600, os.ModeSymlink},
	{"testlink4", 0600, os.ModeSymlink},
	{"testlink5", 0777, os.ModeSymlink},
	{"testlink6", 0200, os.ModeSymlink},
}

const TestDataFileSearchAll = `
---
path: '%v'
`

const TestDataFileSearchPermission = `---
"path": '%v'
"perm": '%o'
`
const TestDataFileSearchAllBitsPermission = `---
"path": '%v'
"perm": '-%o'
`
const TestDataFileSearcByFileType = `
---
path: '%v'
fileType: '%v'
`

const TestDataFileSearchByFileTypeAndPermission = `
---
path: '%v'
fileType: '%v'
perm: '%o'
`

const TestDataFileSearchByNameFilterAndPerm = `
---
path: '%v'
fileType: '%v'
perm: '%o'
searchTerm: '%v'
searchType: '%v'
`
const TestDataFileSearchByNameFilter = `
---
path: '%v'
fileType: '%v'
searchTerm: '%v'
searchType: '%v'
`

var TarHeadersForTests = []byte(`
[
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-21T03:55:52+03:00",
        "Mode": 16877,
        "Name": "bin/",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 53,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2015-12-10T18:41:54+02:00",
        "Mode": 33261,
        "Name": "bin/keyctl",
        "PAXRecords": null,
        "Size": 30792,
        "Typeflag": 48,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-21T03:56:55+03:00",
        "Mode": 16877,
        "Name": "etc/",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 53,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-21T03:55:42+03:00",
        "Mode": 16877,
        "Name": "etc/X11/",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 53,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-21T03:56:31+03:00",
        "Mode": 16877,
        "Name": "etc/X11/Xsession.d/",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 53,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2018-03-28T15:07:34+03:00",
        "Mode": 33188,
        "Name": "etc/X11/Xsession.d/60xdg-user-dirs-update",
        "PAXRecords": null,
        "Size": 80,
        "Typeflag": 48,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2018-06-14T23:06:41+03:00",
        "Mode": 33188,
        "Name": "etc/X11/Xsession.d/90gpg-agent",
        "PAXRecords": null,
        "Size": 608,
        "Typeflag": 48,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-21T03:56:47+03:00",
        "Mode": 16877,
        "Name": "etc/alternatives/",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 53,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "/usr/bin/pinentry-curses",
        "ModTime": "2019-04-21T03:55:41+03:00",
        "Mode": 41471,
        "Name": "etc/alternatives/pinentry",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 50,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "/usr/share/man/man1/pinentry-curses.1.gz",
        "ModTime": "2019-04-21T03:55:41+03:00",
        "Mode": 41471,
        "Name": "etc/alternatives/pinentry.1.gz",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 50,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "/usr/bin/scp",
        "ModTime": "2019-04-21T03:56:24+03:00",
        "Mode": 41471,
        "Name": "etc/alternatives/rcp",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 50,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "/usr/share/man/man1/scp.1.gz",
        "ModTime": "2019-04-21T03:56:24+03:00",
        "Mode": 41471,
        "Name": "etc/alternatives/rcp.1.gz",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 50,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "/usr/bin/file-rename",
        "ModTime": "2019-04-21T03:56:47+03:00",
        "Mode": 41471,
        "Name": "etc/alternatives/rename",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 50,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "/usr/share/man/man1/file-rename.1p.gz",
        "ModTime": "2019-04-21T03:56:47+03:00",
        "Mode": 41471,
        "Name": "etc/alternatives/rename.1.gz",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 50,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "/usr/bin/slogin",
        "ModTime": "2019-04-21T03:56:24+03:00",
        "Mode": 41471,
        "Name": "etc/alternatives/rlogin",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 50,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "/usr/share/man/man1/slogin.1.gz",
        "ModTime": "2019-04-21T03:56:24+03:00",
        "Mode": 41471,
        "Name": "etc/alternatives/rlogin.1.gz",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 50,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "/usr/bin/ssh",
        "ModTime": "2019-04-21T03:56:24+03:00",
        "Mode": 2468,
        "Name": "etc/alternatives/rsh",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 50,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "/usr/share/man/man1/ssh.1.gz",
        "ModTime": "2019-04-21T03:56:24+03:00",
        "Mode": 41471,
        "Name": "etc/alternatives/rsh.1.gz",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 50,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-09T19:54:58+03:00",
        "Mode": 16877,
        "Name": "etc/apparmor/",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 53,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-21T03:56:53+03:00",
        "Mode": 16877,
        "Name": "etc/apparmor.d/",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 53,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-21T03:55:44+03:00",
        "Mode": 16877,
        "Name": "etc/apparmor.d/disable/",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 53,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "/etc/apparmor.d/usr.sbin.rsyslogd",
        "ModTime": "2019-04-21T03:55:44+03:00",
        "Mode": 41471,
        "Name": "etc/apparmor.d/disable/usr.sbin.rsyslogd",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 50,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-21T03:56:11+03:00",
        "Mode": 16877,
        "Name": "etc/apparmor.d/force-complain/",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 53,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "/etc/apparmor.d/usr.sbin.sssd",
        "ModTime": "2019-04-21T03:56:11+03:00",
        "Mode": 41471,
        "Name": "etc/apparmor.d/force-complain/usr.sbin.sssd",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 50,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-21T03:56:53+03:00",
        "Mode": 16877,
        "Name": "etc/apparmor.d/local/",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 53,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-21T03:56:19+03:00",
        "Mode": 33188,
        "Name": "etc/apparmor.d/local/usr.sbin.ntpd",
        "PAXRecords": null,
        "Size": 120,
        "Typeflag": 48,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-21T03:56:22+03:00",
        "Mode": 33188,
        "Name": "etc/apparmor.d/local/usr.sbin.rsyslogd",
        "PAXRecords": null,
        "Size": 124,
        "Typeflag": 48,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-21T03:56:53+03:00",
        "Mode": 33188,
        "Name": "etc/apparmor.d/local/usr.sbin.sssd",
        "PAXRecords": null,
        "Size": 120,
        "Typeflag": 48,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2019-04-21T03:56:18+03:00",
        "Mode": 16877,
        "Name": "etc/apparmor.d/tunables/",
        "PAXRecords": null,
        "Size": 0,
        "Typeflag": 53,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    },
    {
        "AccessTime": "0001-01-01T00:00:00Z",
        "ChangeTime": "0001-01-01T00:00:00Z",
        "Devmajor": 0,
        "Devminor": 0,
        "Format": 2,
        "Gid": 0,
        "Gname": "",
        "Linkname": "",
        "ModTime": "2018-07-06T23:11:36+03:00",
        "Mode": 33188,
        "Name": "etc/apparmor.d/tunables/ntpd",
        "PAXRecords": null,
        "Size": 554,
        "Typeflag": 48,
        "Uid": 0,
        "Uname": "",
        "Xattrs": null
    }
]
`)
