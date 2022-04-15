from pyhanko.sign import signers, timestamps
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko_certvalidator import ValidationContext


def sign_with_timestamp():
    cms_signer = signers.SimpleSigner.load("./myKey.pem", "./cert.pem")

    tst_client = timestamps.HTTPTimeStamper("https://freetsa.org/tsr")

    with open("sample.pdf", "rb") as inf:
        if cms_signer:
            with open("signed-timestamp.pdf", "wb") as outf:
                w = IncrementalPdfFileWriter(inf)
                signers.sign_pdf(
                    w,
                    signers.PdfSignatureMetadata(field_name="Signature1"),
                    signer=cms_signer,
                    timestamper=tst_client,
                    output=outf,
                )


def sign_pades():
    signer = signers.SimpleSigner.load_pkcs12(pfx_file="./keyStore.p12")

    timestamper = timestamps.HTTPTimeStamper(url="https://freetsa.org/tsr")

    signature_meta = signers.PdfSignatureMetadata(
        field_name="Signature",
        md_algorithm="sha256",
        subfilter=SigSeedSubFilter.PADES,
        validation_context=ValidationContext(allow_fetching=True),
        embed_validation_info=True,
        use_pades_lta=True,
    )

    with open("sample.pdf", "rb") as inf:
        w = IncrementalPdfFileWriter(inf)
        if signer:
            with open("signed-pades.pdf", "wb") as outf:
                signers.sign_pdf(
                    w,
                    signature_meta=signature_meta,
                    signer=signer,
                    timestamper=timestamper,
                    output=outf,
                )


if __name__ == "__main__":
    sign_with_timestamp()
