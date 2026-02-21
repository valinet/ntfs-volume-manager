.PHONY: all
all: setdio

setdio: setdio.S
	nasm -f bin $< -o $@ && chmod +x $@

.PHONY: clean
clean:
	rm -rf *.o setdio