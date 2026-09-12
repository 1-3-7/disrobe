Naming a NativeAOT fixture project

Each executable in this directory is published from a small .NET project that lives outside the
repository. Three settings in that project reach the committed artifact, so choose them before the
first build rather than after.

Assembly name

The assembly name becomes the module name inside the executable and the symbol prefix in the
linker map, so it is readable in the committed binary and in the committed link map beside it.
Name it after the fixture file, for example managed_abi_net9_x86_64. When the project file carries
no AssemblyName the name of the project file is used instead, so rename the project file too.

PathMap

PathMap replaces the project directory in any path the compiler would otherwise embed, which is
what keeps a real build directory out of the published binary. Use a target derived from the
fixture, in the form C:\src\<fixture-stem>, for example C:\src\managed_abi_net9_x86_64.

The value does not appear in the executable as a string. It does feed the assembly identity, so two
builds that differ only in their PathMap value produce executables that differ in that field.
Record the value in the build note next to the fixture, because the recorded recipe has to describe
the build that produced the committed bytes.

PDBALTPATH

Pass /PDBALTPATH:%_PDB% to the linker so the debug directory carries a bare file name instead of
the absolute path of the build directory. The oldest fixtures here predate this setting and still
carry such a path.

What these names may not contain

None of the three may name the task, ticket or work item that produced the fixture. A reader of the
published repository cannot resolve such a name, and it describes how the work was scheduled rather
than what the fixture is.

This cannot be corrected after the fact. The assembly name is written into the binary, the PathMap
value determines part of its identity, and the build notes have to keep describing the build that
actually produced the committed bytes. Editing the notes alone would leave them describing a build
that never happened, which is a worse defect than an awkward name. Some fixtures here were built
before this rule and keep their original names for exactly that reason.
