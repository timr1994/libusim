# libusim: Libary for Userspace Software Integrity Measurement

**WARNING: This is proof-of-concept code. It is here for informational purposes only. Please do not use it in production.**

The code in this repository accompanies our publication on "Userspace Software Integrity Measurement" at the *The 16th International Conference on Availability, Reliability and Security* (ARES 2021).

---

Uses the Docker enviorment from [CHARRA](https://github.com/Fraunhofer-SIT/charra) as base.

## TODO
- [x] function addEntry(PCR, interpreter, file, hash)
- [ ] callback


## Build and Run in Docker

1. Install Docker.

2. Build Docker image:

       ./docker/build.sh

3. Run Docker image:

       ./docker/run.sh



## Build

1. Install all dependencies that are needed for the [TPM2-TSS](https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md).

2. Compile libraries:

   Either dynamically linked (default):

       make -j libs

3. Install libraries:

       sudo make libs.install

4. Compile programs:

    Either dynamically linked (default):

       make -j



## Further Preparation

1. Download and install [IBM's TPM 2.0 Simulator](https://sourceforge.net/projects/ibmswtpm2/).

2. Download and install the [TPM2 Tools](https://github.com/tpm2-software/tpm2-tools).



## Run

1. Start the TPM Simulator (and remove the state file `NVChip`):

       cd /tmp ; pkill tpm_server ; rm -f NVChip
       (/usr/local/bin/tpm_server > /dev/null &)

2. Send TPM startup command:

       /usr/local/bin/tpm2_startup -Tmssim --clear


