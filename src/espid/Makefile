.PHONY: all
all: espid
	cp $< ../../fs/bin/.

espid: custom.ld espid.o syscall.o
	$(LD) $(filter-out $<,$^) -o $@ -T $< --strip-all -z noexecstack

espid.o: espid.c
	$(CC) -Wall -c -Os -fno-builtin -fno-ident -fno-asynchronous-unwind-tables -fno-stack-protector -fomit-frame-pointer -fno-pie $< -o $@

syscall.o: syscall.S
	as $< -o $@

.PHONY: clean
clean:
	rm -rf *.o espid