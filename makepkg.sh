apt-get install devscripts;
mkdir DEBIAN
cd DEBIAN
touch control
echo "Package: YellowShark
Version: 1.0
Section: base
Priority: optional
Architecture: all
Depends: libx11-data, libpcap0.8, netbase, fonts-droid, libgl1-mesa-dri, gnome-themes-standard-data, libgl1-mesa-glx, qt5-default
Maintainer: Glouglou
Description: Wireshark like" > control
touch postint
touch postrm
chmod 755 post*
cd ..
mkdir usr
cd usr
mkdir bin
cp ../YellowShark bin/
mkdir share
cd share
mkdir doc
touch README
echo "read me content" > README
touch copyright
echo "Glouglou's crew all right reserved" > copyright
touch changelog
touch changelog.Debian
cd ../../../
echo $PWD
sudo dpkg-deb --build YellowShark
