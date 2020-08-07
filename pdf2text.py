import PyPDF2, requests

response = requests.get('https://blog.nullforge.net/wp-content/uploads/2018/11/rtfm-red-team-field-manual.pdf',verify=False)

arquivo = "teste"
with open('{}.pdf'.format(arquivo), 'wb+') as f:
    f.write(response.content)
    pdf_document = PyPDF2.PdfFileReader(f)
    for n in range(0,pdf_document.getNumPages()):
      first_page = pdf_document.getPage(n)
      print(first_page.extractText())