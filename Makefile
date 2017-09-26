all:
	cargo build

release:
	cargo build --release

clean:
	cargo clean

.PHONY: all clean
