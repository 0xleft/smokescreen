obj-m += smokescreen.o
kmod_name = smokescreen

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	echo "#include <linux/module.h>" > tmp.c
	echo "#include <syscall.h>" >> tmp.c
	echo "#include <stdio.h>" >> tmp.c
	echo "" >> tmp.c
	xxd -i $(kmod_name).ko >> tmp.c
	echo "const char args[] = \"\\\0\";" >> tmp.c
	echo "" >> tmp.c
	cat stub.c >> tmp.c
	cat tmp.c | sed 's/example_ko/$(kmod_name)_ko/g' > load.c
	gcc -o smokescreen load.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm smokescreen