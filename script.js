// credits https://github.com/vbuch/node-signpdf/blob/master/src/signpdf.test.js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const forge = require('node-forge');
const PDFDocument = require('pdfkit');

const DEFAULT_BYTE_RANGE_PLACEHOLDER = '**********';
const certPath = path.join(__dirname, 'certs', 'certificate.p12');
const PKCS12_CERT_BAG = '1.2.840.113549.1.12.10.1.3';
const PKCS12_KEY_BAG = '1.2.840.113549.1.12.10.1.2';


let signedPDFFileRelativePath = path.join(__dirname, 'output', `${Date.now()}.pdf`);
let unSignedPDFFileRelativePath = path.join(__dirname, 'output',`${Date.now()}-unsigned.pdf`);


const addSignaturePlaceholder = ({
    pdf,
    reason,
    signatureLength = 4096
  }) => {
    /* eslint-disable no-underscore-dangle,no-param-reassign */
    // Generate the signature placeholder
    const signature = pdf.ref({
      Type: 'Sig',
      Filter: 'Adobe.PPKLite',
      SubFilter: 'adbe.pkcs7.detached',
      ByteRange: [
        0,
        DEFAULT_BYTE_RANGE_PLACEHOLDER,
        DEFAULT_BYTE_RANGE_PLACEHOLDER,
        DEFAULT_BYTE_RANGE_PLACEHOLDER,
      ],
      Contents: Buffer.from(String.fromCharCode(0).repeat(signatureLength)),
      Reason: new String(reason), // eslint-disable-line no-new-wrappers
      M: new Date(),
    });

    // Generate signature annotation widget
    const widget = pdf.ref({
      Type: 'Annot',
      Subtype: 'Widget',
      FT: 'Sig',
      Rect: [0, 0, 0, 0],
      V: signature,
      T: new String('Signature1'), // eslint-disable-line no-new-wrappers
      F: 4,
      P: pdf._root.data.Pages.data.Kids[0], // eslint-disable-line no-underscore-dangle
    });
    // Include the widget in a page
    pdf._root.data.Pages.data.Kids[0].data.Annots = [widget];

    // Create a form (with the widget) and link in the _root
    const form = pdf.ref({
      SigFlags: 3,
      Fields: [widget],
    });
    pdf._root.data.AcroForm = form;

    return {
      signature,
      form,
      widget,
    };
    /* eslint-enable no-underscore-dangle,no-param-reassign */
  };

  const creatPDF = (invoiceObj) => new Promise((resolve) => {
    const doc = new PDFDocument({
      autoFirstPage: true,
      size: 'A4',
      layout: 'portrait',
      bufferPages: true,
    });

    doc.info = {
      Title: 'E-Invoice',
      Author: 'author',
      Subject: invoiceObj.invoiceId,
      CreationDate: new Date(),
      ModDate: new Date()
    }

    doc.fillColor('black')
    doc.fontSize(15)
      .text('E-Invoice Egypt', 300, 40, {
        align: 'right',
      })

    doc.fillColor('gray')
    doc.fontSize(10)
      .text(`Seller: Apple Egypt`, 30, 100, {
        align: 'left',
      })

    doc.fontSize(10)
      .text(`Customer: Sony Egypt`, 30, 115, {
        align: 'left',
      })

    doc.fontSize(10)
      .text(`Invoice ID: 12jhasjdh-834jjsjad-2384masdn`, 30, 130, {
        align: 'left',
      })

    doc.fillColor('black')
    doc.fontSize(10)
      .text(`Item Name        Item Quantity        Item Price        Item Category        Total Price`, 130, 180, {
        align: 'justify',
        underline: true
      })

    //for loop to render items here
    doc.fillColor('blue')
    doc.fontSize(10)
      .text(`f7                     12                       3000                      It                        23894`, 150, 200, {
        align: 'justify',
      })

    doc.fillColor('blue')
    doc.fontSize(10)
      .text(`f7                     12                       3000                      It                        23894`, 150, 220, {
        align: 'justify',
      })

    doc.fillColor('gray')
    doc.fontSize(10)
      .text(`Total Price Without VAT: 32323`, 30, 500, {
        align: 'justify',
      })

    doc.fillColor('gray')
    doc.fontSize(10)
      .text(`Total Price With VAT: 3232234`, 30, 515, {
        align: 'justify',
      })

    doc.fillColor('gray')
    doc.fontSize(10)
      .text(`Total VAT: 23423`, 30, 530, {
        align: 'justify',
      })

    doc.fillColor('red')
    doc.moveDown()
    doc.text('This Document Is Signed And Certified By company', 100, 750, {
      align: 'right'
    })

    doc.image('certified.png', 20, 700, {
      width: 130,
      height: 80,
      align: 'left'
    })


    const pdfChunks = [];
    doc.on('data', (data) => {
      pdfChunks.push(data);
    });
    doc.on('end', () => {
      resolve(Buffer.concat(pdfChunks));
    });

    const refs = addSignaturePlaceholder({
      pdf: doc,
      reason: 'I am the author',
      signatureLength: 4096,
    });

    Object.keys(refs).forEach(key => refs[key].end());

    doc.end();
  });

const signPDF = (pdfBuffer, p12Buffer)  => {
    if (!(pdfBuffer instanceof Buffer)) {
        throw new Error(
            'PDF expected as Buffer.'
        );
    }
    if (!(p12Buffer instanceof Buffer)) {
        throw new Error(
            'p12 certificate expected as Buffer.'
        );
    }

    let pdf = pdfBuffer;
    const lastChar = pdfBuffer.slice(pdfBuffer.length - 1).toString();
    if (lastChar === '\n') {
        // remove the trailing new line
        pdf = pdf.slice(0, pdf.length - 1);
    }

    const byteRangePlaceholder = [
        0,
        `/${DEFAULT_BYTE_RANGE_PLACEHOLDER}`,
        `/${DEFAULT_BYTE_RANGE_PLACEHOLDER}`,
        `/${DEFAULT_BYTE_RANGE_PLACEHOLDER}`,
    ];
    const byteRangeString = `/ByteRange [${byteRangePlaceholder.join(' ')}]`;
    const byteRangePos = pdf.indexOf(byteRangeString);
    if (byteRangePos === -1) {
        throw new Error(
            `Could not find ByteRange placeholder: ${byteRangeString}`
        );
    }
    const byteRangeEnd = byteRangePos + byteRangeString.length;
    const contentsTagPos = pdf.indexOf('/Contents ', byteRangeEnd);
    const placeholderPos = pdf.indexOf('<', contentsTagPos);
    const placeholderEnd = pdf.indexOf('>', placeholderPos);
    const placeholderLengthWithBrackets = (placeholderEnd + 1) - placeholderPos;
    const placeholderLength = placeholderLengthWithBrackets - 2;
    const byteRange = [0, 0, 0, 0];
    byteRange[1] = placeholderPos;
    byteRange[2] = byteRange[1] + placeholderLengthWithBrackets;
    byteRange[3] = pdf.length - byteRange[2];
    let actualByteRange = `/ByteRange [${byteRange.join(' ')}]`;
    actualByteRange += ' '.repeat(byteRangeString.length - actualByteRange.length);

    // Replace the /ByteRange placeholder with the actual ByteRange
    pdf = Buffer.concat([
        pdf.slice(0, byteRangePos),
        Buffer.from(actualByteRange),
        pdf.slice(byteRangeEnd),
    ]);

    // Remove the placeholder signature
    pdf = Buffer.concat([
        pdf.slice(0, byteRange[1]),
        pdf.slice(byteRange[2], byteRange[2] + byteRange[3]),
    ]);

    const forgeCert = forge.util.createBuffer(p12Buffer.toString('binary'));
    const p12Asn1 = forge.asn1.fromDer(forgeCert);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, '');
    // get bags by type
    const certBags = p12.getBags({bagType: PKCS12_CERT_BAG})[PKCS12_CERT_BAG];
    const keyBags = p12.getBags({bagType: PKCS12_KEY_BAG})[PKCS12_KEY_BAG];

    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(pdf.toString('binary'));
    p7.addCertificate(certBags[0].cert);

    p7.addSigner({
        key: keyBags[0].key,
        certificate: certBags[0].cert,
        digestAlgorithm: forge.pki.oids.sha256,
        authenticatedAttributes: [
            {
                type: forge.pki.oids.contentType,
                value: forge.pki.oids.data,
            }, {
                type: forge.pki.oids.messageDigest,
                // value will be auto-populated at signing time
            }, {
                type: forge.pki.oids.signingTime,
                // value can also be auto-populated at signing time
                value: new Date(),
            },
        ],
    });
    p7.sign({detached: true});

    const raw = forge.asn1.toDer(p7.toAsn1()).getBytes();
    debugger;

    if (raw.length > placeholderLength) {
        throw new Error(
            `Signature exceeds placeholder length: ${raw.length} > ${placeholderLength}`
        );
    }

    let signature = Buffer.from(raw, 'binary').toString('hex');

    // placeholderLength is for the HEX symbols and we need the raw char length
    const placeholderCharCount = placeholderLength / 2;

    // Pad with zeroes so the output signature is the same length as the placeholder
    signature += Buffer
        .from(String.fromCharCode(0).repeat(placeholderCharCount - raw.length))
        .toString('hex');

    pdf = Buffer.concat([
        pdf.slice(0, byteRange[1]),
        Buffer.from(`<${signature}>`),
        pdf.slice(byteRange[1]),
    ]);

    return pdf;
};


  const signFunc = async () => {
    const pdfBuffer = await creatPDF({
      invoiceId: 'asdasdjkayduweydwuedfhwu3dhweudhwd'
    });
    const signedPdf = signPDF(
      pdfBuffer,
      fs.readFileSync(certPath)
    );

    fs.writeFileSync(signedPDFFileRelativePath, signedPdf);
  }

  // const hexStr = (input) => {
  //   let output = '';
  //   for (let i = 0; i < input.length; i += 2) {
  //       output += String.fromCharCode(parseInt(input.substr(i, 2), 16));
  //   }
  //   return output;
  // };

  const extractSignature = (pdf) => {
    const byteRangePos = pdf.indexOf('/ByteRange [');
    if (byteRangePos === -1) {
        throw new Error('Failed to locate ByteRange.');
    }

    const byteRangeEnd = pdf.indexOf(']', byteRangePos);
    if (byteRangeEnd === -1) {
        throw new Error('Failed to locate the end of the ByteRange.');
    }

    const byteRange = pdf.slice(byteRangePos, byteRangeEnd + 1).toString();
    const matches = (/\/ByteRange \[(\d+) +(\d+) +(\d+) +(\d+)\]/).exec(byteRange);
    console.log('matches', matches);

    let signedData = pdf.slice(
        parseInt(matches[1]),
        parseInt(matches[1]) + parseInt(matches[2]),
    ).toString('binary');
    signedData += pdf.slice(
        parseInt(matches[3]),
        parseInt(matches[3]) + parseInt(matches[4]),
    ).toString('binary');

    let signatureHex = pdf.slice(
        parseInt(matches[1]) + parseInt(matches[2]) + 1,
        parseInt(matches[3]) - 1,
    ).toString('binary');
    signatureHex = signatureHex.replace(/(?:00)*$/, '');
    const signature = Buffer.from(signatureHex, 'hex').toString('binary');
    debugger;
    return {signature, signedData};
  };


  function verify() {
    debugger;

    // let pdfParser = new PDFParser();

    //   pdfParser.on("pdfParser_dataError", errData => console.error(errData.parserError) );
    //   pdfParser.on("pdfParser_dataReady", pdfData => {
    //       // fs.writeFile("./pdf2json/test/F1040EZ.json", JSON.stringify(pdfData));
    //       debugger;
    //   });

    // pdfParser.loadPDF(pdfPath);

  const pdf = fs.readFileSync(signedPDFFileRelativePath);
debugger;
  const extractedData = extractSignature(pdf);
  fs.writeFileSync(unSignedPDFFileRelativePath, extractedData.unSignedData)
  // const buffer = forge.util.createBuffer();
  // buffer.putBytes(extractedData.signature);
  const p7Asn1 = forge.asn1.fromDer(extractedData.signature);
  const message = forge.pkcs7.messageFromAsn1(p7Asn1);
  const sig = message.rawCapture.signature;
  // const pem = forge.pkcs7.messageToPem(message);
  const cert = forge.pki.certificateToPem(message.certificates[0]);

  var verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(extractedData.signedData, 'binary');
  var verified = verifier.verify(cert, sig, 'binary');
  debugger;
    // pkg_sig is the extracted Signature from the S/MIME
    // with added -----BEGIN PKCS7----- around it
    // var msg = forge.pkcs7.messageFromPem(pkg_sig);
    // var sig = msg.rawCapture.signature;

    // pkg is the "clean" signed data from the S/MIME
    // var buf = signature.signedData;

  //   var verifier = crypto.createVerify("RSA-SHA256");
  //   verifier.update(buf);
  //   // var verified = verifier.verify(publicKey, extractedData.signature, 'base64');
  // debugger;
  //   console.log(verified);
  }

async function main () {
  await signFunc();
  debugger;
  verify();
}


  main();
