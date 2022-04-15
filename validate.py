from pyhanko.sign.general import load_cert_from_pemder
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp

root_cert = load_cert_from_pemder("./cert.pem")
tsa_root_cert = load_cert_from_pemder("cacert.cer")
vc = ValidationContext(trust_roots=[root_cert])
tsa_vc = ValidationContext(trust_roots=[tsa_root_cert])

with open("signed-timestamp.pdf", "rb") as doc:
    r = PdfFileReader(doc)
    sig = r.embedded_signatures[0]
    status = validate_pdf_signature(sig, vc, tsa_vc)
    print(status.pretty_print_details())
    print("Is valid:", status.trusted)
    if status.timestamp_validity:
        print("Timestamp is valid:", status.timestamp_validity.trusted)
