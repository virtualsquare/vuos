BUILDDIR=build

all: clean builddir fcntl_lock.c flock_lock.c fcntl_other.c dllock
	gcc -g -o $(BUILDDIR)/fcntl_lock fcntl_lock.c
	gcc -g -o $(BUILDDIR)/fcntl_other fcntl_other.c
	gcc -g -o $(BUILDDIR)/flock_lock flock_lock.c

dllock: dllock.c
	gcc -g -shared -fPIC -o build/dllock.so dllock.c -ldl

builddir:
	mkdir $(BUILDDIR)

clean:
	rm -rf $(BUILDDIR)
