# Comment/uncomment the following line to disable/enable debugging
 DEBUG = y

# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  DEBFLAGS = -O -g -DSRVTABLES_DEBUG # "-O" is needed to expand inlines
endif

ccflags-y += $(DEBFLAGS)

#obj-m += translog.o
#obj-m += weblog.o
obj-m	+=skb_post.o
obj-m	+=skb_pre.o
obj-m	+=tcp_post_clone.o

KDIR = /lib/modules/$(shell uname -r)/build
MDIR = $(PWD)

INS_KO=weblog
INS_ROOT = /usr/local/$(INS_KO)

# copy to INS_ROOT
INS_SCRIPTS = runweblog.sh weblogd README
#INS_DIR = 

all:
	make -C $(KDIR) M=$(MDIR) modules
#	gcc -g weblogd.c -o weblogd

clean:
	rm -f *~ weblogd
	make -C $(KDIR) M=$(MDIR) clean 

install:
	mkdir $(INS_ROOT)
	cp $(INS_KO).ko $(INS_ROOT)
	cp $(INS_SCRIPTS) $(INS_ROOT)
#	cp -r $(INS_DIR) $(INS_ROOT)

uninstall:
#	rm -f $(INS_ROOT)/$(INS_DIR)/*
#	rmdir $(INS_ROOT)/$(INS_DIR)
	rm -f $(INS_ROOT)/*
	rmdir $(INS_ROOT)
