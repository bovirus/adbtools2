# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.8] - 1018-08-19

### Added

* [mod-kit] possibility to remove files before the creation of the jffs2 image
  of the new root file system, with `root-rm-files.txt`

* [mod-kit] possibility to specify a root password, to `mod-kit-run.sh`, to be
  included in the jffs2 image of the new root file system

### Changed

* [mod-kit] default root password changed from not needed to "**no.wordpass**"
(changed file `root-patch/etc/passwd.orig.patch`)

## [v0.7] - 2018-08-16

### First release

The software is fully functional but with some limitations that could
be removed in future releases:

* [mod-kit] only the DVA-5592_A1_WI_20180405.sig firmware can be modified
  (firmware for the device D-Link DVA-5592 distributed in Italy by
  Wind and released on 2018/04/05)

* [mod-kit] new root file system image, incorporating custom modifications, must
  not be greater than current root file system image size
