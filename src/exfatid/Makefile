.PHONY: all
all: exfatid
	cp $< ../../fs/bin/.

exfatid: custom.ld exfatid.o syscall.o
	$(LD) $(filter-out $<,$^) -o $@ -T $< --strip-all -z noexecstack

exfatid.o: exfatid.c
	$(CC) -Wall -c -Os -fno-builtin -fno-ident -fno-asynchronous-unwind-tables -fno-stack-protector -fomit-frame-pointer -fno-pie $< -o $@

syscall.o: syscall.S
	as $< -o $@

.PHONY: clean
clean:
	rm -rf *.o exfatid