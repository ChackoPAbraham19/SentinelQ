import sys
import zipfile
import xml.etree.ElementTree as ET

def extract_docx(path):
    with zipfile.ZipFile(path) as z:
        xml = z.read('word/document.xml')
    tree = ET.fromstring(xml)
    ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    paragraphs = []
    for p in tree.findall('.//w:p', ns):
        texts = [t.text for t in p.findall('.//w:t', ns) if t.text]
        if texts:
            paragraphs.append(''.join(texts))
    return '\n\n'.join(paragraphs)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python extract_docx.py path/to/file.docx')
        sys.exit(1)
    path = sys.argv[1]
    try:
        text = extract_docx(path)
        print(text)
    except Exception as e:
        print('Error:', e)
        sys.exit(2)
