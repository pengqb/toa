sudo rmmod nf_to_add
make clean
make
sudo insmod nf_to_add.ko outPort=4321