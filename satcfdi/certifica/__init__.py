import base64
import hashlib
import io
import os.path
from datetime import datetime
from random import randbytes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding as sym_padding

from .pkcs7 import create_pkcs7
from ..models import Signer, Certificate, RFC, RFCType
from ..ans1e import *
from ..models.certificate import CertificateType
from ..zip import zip_create, ZipData

from asn1crypto import keys, core, pem
from asn1crypto import x509 as asn1_x509, csr, algos

ENCODING = 'windows-1252'


def _p_join(dirname, filename):
    if dirname is None:
        return filename
    os.makedirs(dirname, exist_ok=True)
    return os.path.join(dirname, filename)


class Certifica:
    def __init__(self, signer: Signer):
        self.signer = signer
        if self.signer.type != CertificateType.Fiel:
            raise ValueError("'signer' no es Fiel")

    def generacion_fiel(self, password: str, rfc: str, curp: str, correo: str = None, dirname: str = None):
        tmf = datetime.now().strftime('%Y%m%d_%H%M%S')
        key_filename = f"Claveprivada_FIEL_{self.signer.rfc}_{tmf}.key"
        private_key = self._generate_key(_p_join(dirname, key_filename), password)

        ren_filename = f"Renovacion_FIEL_{self.signer.rfc}_{tmf}.req"
        data = _create_generacion_certificate_signing_request(private_key=private_key, rfc=rfc, curp=curp, correo=correo)
        with open(_p_join(dirname, ren_filename), 'wb') as f:
            f.write(data)

    def renovacion_fiel(self, password: str, correo: str = None, dirname: str = None):
        tmf = datetime.now().strftime('%Y%m%d_%H%M%S')
        key_filename = f"Claveprivada_FIEL_{self.signer.rfc}_{tmf}.key"
        private_key = self._generate_key(_p_join(dirname, key_filename), password)

        ren_filename = f"Renovacion_FIEL_{self.signer.rfc}_{tmf}.ren"
        data = _create_renovation_certificate_signing_request(signer=self.signer, private_key=private_key, correo=correo)
        pck = self._pkcs7_package(data)
        with open(_p_join(dirname, ren_filename), 'wb') as f:
            f.write(pck)

    def renovacion_fiel_moral(self, password: str, rfc: str, correo: str, dirname: str = None):
        rfc = RFC(rfc)
        if rfc.type != RFCType.MORAL:
            raise ValueError("RFC no es Moral")
        rfc = str(rfc)

        tmf = datetime.now().strftime('%Y%m%d_%H%M%S')
        key_filename = f"Claveprivada_FIEL_{rfc}_{tmf}.key"
        private_key = self._generate_key(_p_join(dirname, key_filename), password)

        ren_filename = f"Renovacion_FIEL_{rfc}_{tmf}.ren"
        data = _create_renovation_moral_certificate_signing_request(
            signer=self.signer,
            private_key=private_key,
            rfc=rfc,
            correo=correo
        )
        pck = self._pkcs7_package(data)
        with open(_p_join(dirname, ren_filename), 'wb') as f:
            f.write(pck)

    def solicitud_certificado(self, sucursal: str, password: str, dirname: str = None):
        tmf = datetime.now().strftime('%Y%m%d_%H%M%S')
        key_filename = f"CSD_{sucursal.replace(' ', '_')}_{self.signer.rfc}_{tmf}.key"
        private_key = self._generate_key(_p_join(dirname, key_filename), password)

        sdg_filename = f"CSD_{self.signer.rfc}_{tmf}.sdg"
        data = _create_certificate_signing_request_zip(self.signer, private_key, sucursal)
        pck = self._pkcs7_package(data)
        with open(_p_join(dirname, sdg_filename), 'wb') as f:
            f.write(pck)

    @staticmethod
    def _export_sat_private_key(
            private_key: rsa.RSAPrivateKey,
            password: str,
            cipher_alg: str = "3DES"
    ) -> bytes:
        """
        Exporta la llave privada RSA al formato propietario del SAT.

        El SAT usa PKCS#8 / PBES2 con una variación:
          - Salt = bytes [30:38] del DER sin cifrar de la llave
          - Iteraciones PBKDF2 = tamaño de llave RSA en bits (ej: 2048)
          - Cifrado: 3DES-CBC ó AES-256-CBC
          - HMAC: SHA1

        Args:
            private_key: Llave privada RSA.
            password: Contraseña para proteger el archivo .key.
            cipher_alg: "3DES" (por defecto, formato clásico) ó "AES256".

        Returns:
            Bytes del archivo .key en formato DER.
        """
        unenc_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        if len(unenc_der) < 38:
            raise ValueError("DER inválido: muy corto para extraer salt")

        # El SAT elige el salt de una posición específica del DER sin cifrar
        salt = unenc_der[30:38]
        iterations = private_key.key_size

        cipher_alg_upper = cipher_alg.upper()
        if cipher_alg_upper in ('3DES', 'DES-EDE3-CBC', 'TRIPLEDES'):
            key_len = 24  # 192 bits
            iv_len = 8
            algo_oid = 'tripledes_3key'
            block_bits = 64
        elif cipher_alg_upper in ('AES256', 'AES-256-CBC'):
            key_len = 32  # 256 bits
            iv_len = 16
            algo_oid = 'aes256_cbc'
            block_bits = 128
        else:
            raise ValueError(f"Algoritmo no soportado: {cipher_alg}")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=key_len + iv_len,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        material = kdf.derive(password.encode('utf-8'))
        derived_key = material[:key_len]
        iv = material[key_len:]

        padder = sym_padding.PKCS7(block_bits).padder()
        padded_data = padder.update(unenc_der) + padder.finalize()

        if key_len == 24:
            # Use decrepit path to avoid DeprecationWarning in cryptography >= 44
            try:
                from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            except ImportError:
                from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
            cipher_obj = Cipher(TripleDES(derived_key), modes.CBC(iv), backend=default_backend())
        else:
            cipher_obj = Cipher(algorithms.AES(derived_key),
                                modes.CBC(iv), backend=default_backend())

        enc = cipher_obj.encryptor()
        encrypted_data = enc.update(padded_data) + enc.finalize()

        # Construir la estructura ASN.1 PKCS#8 EncryptedPrivateKeyInfo
        pbkdf2_params = algos.Pbkdf2Params({
            'salt': algos.Pbkdf2Salt(name='specified', value=salt),
            'iteration_count': iterations
        })
        pbkdf2_kdf = algos.KdfAlgorithm({'algorithm': 'pbkdf2', 'parameters': pbkdf2_params})
        enc_scheme = algos.EncryptionAlgorithm({'algorithm': algo_oid, 'parameters': core.OctetString(iv)})
        pbes2_params = algos.Pbes2Params({'key_derivation_func': pbkdf2_kdf, 'encryption_scheme': enc_scheme})
        pbes2_alg = keys.EncryptionAlgorithm({'algorithm': 'pbes2', 'parameters': pbes2_params})
        enc_key_info = keys.EncryptedPrivateKeyInfo({
            'encryption_algorithm': pbes2_alg,
            'encrypted_data': encrypted_data
        })
        return enc_key_info.dump()

    @staticmethod
    def _generate_key(key_filename, password):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        p_key = Certifica._export_sat_private_key(private_key, password, cipher_alg="3DES")

        with open(key_filename, 'wb') as f:
            f.write(p_key)

        return private_key

    def _pkcs7_package(self, data):
        return create_pkcs7(
            data=data,
            signer=self.signer,
            hash_algorithm=hashes.SHA1(),
        )


def _create_certificate_signing_request_zip(signer: Signer, private_key: RSAPrivateKey, sucursal: str):
    res = _create_certificate_signing_request(signer=signer, private_key=private_key, sucursal=sucursal)

    tmf = datetime.now().strftime('%Y%m%d_%H%M%S')
    tmp_filename = f"CSD_{sucursal.replace(' ', '_')}_{signer.rfc}_{tmf}s.req"

    with io.BytesIO() as b:
        zip_create(b, files=[ZipData(tmp_filename, lambda s: s.write(res))])
        return b.getvalue()


def _create_generacion_certificate_signing_request(private_key: RSAPrivateKey, rfc: str, curp: str, correo: str):
    code = _calculate_code_random()

    subject = {
        '2.5.4.45': (rfc.encode(ENCODING), Numbers.PrintableString),
        '2.5.4.5': (curp.encode(ENCODING), Numbers.PrintableString),
        '1.2.840.113549.1.9.1': (correo, Numbers.IA5String)
    }

    return _certificate_request(private_key, subject, code)


def _create_renovation_certificate_signing_request(signer: Signer, private_key: RSAPrivateKey, correo):
    code = _calculate_code_random()
    cer = signer.certificate
    subject_at = {
        k: v for k, v in cer.get_subject().get_components()
    }

    subject = {
        '2.5.4.45': (subject_at[b'x500UniqueIdentifier'], Numbers.PrintableString),
        '2.5.4.5': (subject_at[b'serialNumber'], Numbers.PrintableString),
        '1.2.840.113549.1.9.1': (correo or subject_at[b'emailAddress'], Numbers.IA5String)
    }
    return _certificate_request(private_key, subject, code)


def _create_renovation_moral_certificate_signing_request(signer: Signer, private_key: RSAPrivateKey, rfc, correo):
    code = _calculate_code_random()
    cer = signer.certificate
    subject_at = {
        k: v for k, v in cer.get_subject().get_components()
    }

    subject = {
        '2.5.4.45': (rfc.encode(ENCODING) + b' / ' + subject_at[b'x500UniqueIdentifier'], Numbers.PrintableString),
        '2.5.4.5': (b' / ' + subject_at[b'serialNumber'], Numbers.PrintableString),
        '1.2.840.113549.1.9.1': (correo, Numbers.IA5String)
    }
    return _certificate_request(private_key, subject, code)


def _create_certificate_signing_request(signer: Signer, private_key: RSAPrivateKey, sucursal: str):
    code = _calculate_code(signer)
    cer = signer.certificate
    subject_at = {
        k: v for k, v in cer.get_subject().get_components()
    }

    subject = {
        '2.5.4.45': (subject_at[b'x500UniqueIdentifier'], Numbers.PrintableString),
        '2.5.4.5': (subject_at[b'serialNumber'], Numbers.PrintableString)
    }
    if RFC(signer.rfc).type == RFCType.MORAL:
        subject['2.5.4.10'] = (subject_at[b'O'].decode(ENCODING), None)
    else:
        subject['2.5.4.3'] = (subject_at[b'CN'].decode(ENCODING), None)
    subject['2.5.4.11'] = (sucursal, None)

    return _certificate_request(private_key, subject, code)


def _certificate_request(private_key: RSAPrivateKey, subject: dict, code: bytes):
    public_key_bytes = private_key.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.PKCS1)

    e = Ans1Encoder()
    with e.seq():
        e(0)
        with e.seq():
            for k, (v, nr) in subject.items():
                with e.set():
                    with e.seq():
                        e.oid(k)
                        e(v, nr=nr)
        with e.seq():
            with e.seq():
                e.oid('1.2.840.113549.1.1.1')
                e()
            e(public_key_bytes, nr=Numbers.BitString)
        with e.enter(nr=0, cls=Classes.Context):
            with e.seq():
                e.oid('1.2.840.113549.1.9.7')
                with e.set():
                    e(code, nr=Numbers.PrintableString)
    cert_request_bytes = e.output()

    e = Ans1Encoder()
    with e.seq():
        e.write(cert_request_bytes)
        with e.seq():
            e.oid('1.2.840.113549.1.1.5')
            e()
        e(
            private_key.sign(data=cert_request_bytes, padding=padding.PKCS1v15(), algorithm=hashes.SHA1()),
            nr=Numbers.BitString
        )
    return e.output()


def _calculate_code(certificate: Certificate):
    ui = next(v for k, v in certificate.certificate.get_subject().get_components() if k == b'x500UniqueIdentifier')

    def digest(value):
        m = hashlib.sha1()
        m.update(value)
        return base64.b64encode(m.digest())

    return digest(ui + digest(ui + ui))


def _calculate_code_random():
    return base64.b64encode(randbytes(20))
