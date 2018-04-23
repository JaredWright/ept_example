# Bareflank Hypervisor EPT Example

## Description

This example demonstrates how to extend the Bareflank hypervisor to trap read
accesses to a page using the extended page tables.

## Compilation / Usage

To setup this extension, run the following (assuming Linux):

```
git clone https://github.com/bareflank/hypervisor
git clone https://github.com/bareflank/extended_apis
git clone https://github.com/jaredwright/ept_example.git
mkdir build; cd build
cmake ../hypervisor -DCONFIG=ept_example/config.cmake
make -j<# cores + 1>
```

To load this extension, run the following commands:

```
make driver_quick
make quick
```

This extension will trap read access to a page managed by the VMM as the VMM
is being unloaded. Therfore, you will not be able to view this extension's
output from the typical ```make dump``` command. Connect to your enviornment's
serial port to view output using the following:

```
make unload
make driver_unload
```
