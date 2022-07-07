export AFLGO=/home/aflgo
git clone https://gitlab.gnome.org/GNOME/libxml2.git libxml2_ef709ce2

# valid.c:2637
# valid.c:2638
# valid.c:2639
# valid.c:2640


cd libxml2_ef709ce2; git checkout ef709ce2
mkdir obj-aflgo; mkdir obj-aflgo/temp
export SUBJECT=$PWD; export TMP_DIR=$PWD/obj-aflgo/temp
export CC=$AFLGO/afl-clang-fast; export CXX=$AFLGO/afl-clang-fast++
export LDFLAGS=-lpthread
export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
git diff -U0 HEAD^ HEAD > $TMP_DIR/commit.diff

git diff HEAD~7 HEAD~6 > $TMP_DIR/commit.diff

wget https://raw.githubusercontent.com/jay/showlinenum/develop/showlinenum.awk
chmod +x showlinenum.awk
mv showlinenum.awk $TMP_DIR
cat $TMP_DIR/commit.diff |  $TMP_DIR/showlinenum.awk show_header=0 path=1 | grep -e "\.[ch]:[0-9]*:+" -e "\.cpp:[0-9]*:+" -e "\.cc:[0-9]*:+" | cut -d+ -f1 | rev | cut -c2- | rev > $TMP_DIR/BBtargets.txt
cat  $TMP_DIR/BBtargets.txt
./autogen.sh; make distclean
cd obj-aflgo; CFLAGS="$ADDITIONAL" CXXFLAGS="$ADDITIONAL" ../configure --disable-shared --prefix=`pwd`
make clean; make -j4
cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt
#$AFLGO/scripts/genDistance.sh $SUBJECT $TMP_DIR xmllint
$AFLGO/scripts/gen_distance_fast.py $SUBJECT/obj-aflgo $TMP_DIR xmllint
CFLAGS="-distance=$TMP_DIR/distance.cfg.txt" CXXFLAGS="-distance=$TMP_DIR/distance.cfg.txt" ../configure --disable-shared --prefix=`pwd`
make clean; make -j4
mkdir in; cp $SUBJECT/test/dtd* in; cp $SUBJECT/test/dtds/* in
$AFLGO/afl-fuzz -m none -z exp -c 45m -i in -o out ./xmllint --valid --recover @@
$AFLGO/afl-fuzz -t 600+ -m 5000  -z exp -c 45m -i in -o out ./xmllint --valid --recover @@

$AFLGO/afl-fuzz -S ef709ce2 -z exp -c 45m -i in -o out $SUBJECT/xmllint --valid --recover @@


git clone https://gitee.com/suyee0516/libxml2.git
cd libxml2; git checkout ef709ce2
mkdir temp
export CAFL=/sc/CFuzz
export CC=$CAFL/afl-clang-fast; export CXX=$CAFL/afl-clang-fast++
export SUBJECT=$PWD; export TMP_DIR=$PWD/temp
export LDFLAGS=-lpthread

git diff -U0 HEAD^ HEAD > $TMP_DIR/commit.diff
cp /home/showlinenum.awk $TMP_DIR
cat $TMP_DIR/commit.diff |  $TMP_DIR/showlinenum.awk show_header=0 path=1 | grep -e "\.[ch]:[0-9]*:+" -e "\.cpp:[0-9]*:+" -e "\.cc:[0-9]*:+" | cut -d+ -f1 | rev | cut -c2- | rev > $TMP_DIR/bchange.txt
cat $TMP_DIR/bchange.txt

./autogen.sh; make distclean
CFLAGS="-targets=$TMP_DIR/bchange.txt" CXXFLAGS="-targets=$TMP_DIR/bchange.txt" ./configure --disable-shared --prefix=`pwd`
make clean; make -j4
mkdir in; cp $SUBJECT/test/dtd* in; cp $SUBJECT/test/dtds/* in
$CAFL/afl-fuzz -m none -i in -o out ./xmllint --valid --recover @@
$CAFL/afl-fuzz -t 600+ -m 5000  -i - -o out ./xmllint --valid --recover @@




make clean;AFL_USE_ASAN=1 make -j 4
./xmllint --valid --recover /home/asan_aflgo/obj-aflgo/out/crashes/id:000041,31256865,sig:11,src:000701,op:arith8,pos:25,val:+21

tar -zcvf /sc/aflgo_lib.tar.gz ./ASAN_filter


./xmllint --valid --recover ./crashes/