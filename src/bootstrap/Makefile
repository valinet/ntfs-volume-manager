.PHONY: all
all: bootstrap
	cp $< ../../fs/bin/.

bootstrap: custom.ld bootstrap.o syscall.o
	$(LD) $(filter-out $<,$^) -o $@ -T $< --strip-all -z noexecstack

bootstrap.o: bootstrap.c
	$(CC) -Wall -c -Os -fno-builtin -fno-ident -fno-asynchronous-unwind-tables -fno-stack-protector -fomit-frame-pointer -fno-pie $< -o $@

syscall.o: syscall.S
	as $< -o $@

.PHONY: clean
clean:
	rm -rf *.o bootstrap