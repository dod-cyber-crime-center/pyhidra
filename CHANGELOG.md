# Changelog

## Unreleased

## 0.1.3 - 2022-03-30
- Corrected server libjvm locating
- General cleanup

## 0.1.2 - 2022-03-18
- Fixed issue Java Path delimiter
- Fixed issue that caused subprocess to not run correctly on non-windows systems
- Set source target Java version to 11
- Corrected JVM path on non-windows systems
- Added Mac GUI fixes

## 0.1.1 - 2022-01-27
- Fixed issue from mishandled newline in the interpreter panel
- Fixed unstarted transaction when running code that alters a program database in the interpreter panel
- Fixed noise produced from an exception during analysis due to an analyzer using a script without acquiring a bundle host reference
- Fixed exception in open_program from attempting to use a non-public field in `FlatProgramAPI`

## 0.1.0 - 2021-06-14
- Initial release

[Unreleased]: https://github.com/Defense-Cyber-Crime-Center/pyhidra/compare/0.1.3...HEAD
