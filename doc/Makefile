

all: index.html readme.txt

index.html: *.xml
	xsltproc --xinclude \
	         /usr/share/xml/docbook/stylesheet/docbook-xsl/html/docbook.xsl \
	         peccolo.xml \
             >index.html

readme.txt: index.html
	  lynx -dump index.html >readme.txt

clean:
	  rm -rf *.html *.fo *.pdf

