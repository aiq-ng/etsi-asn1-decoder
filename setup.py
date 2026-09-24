from setuptools import setup

setup(
    name='etsi-asn1-decoder',
    version='0.2.1',
    description='ASN.1 BER/DER Decoder for ETSI Specs',
    python_requires='>=3.10',
    author='Samuel Adeshina',
   packages=['etsi_asn1_decoder'],
   install_requires=[
       'asn1tools',
       'orjson',
   ],
   entry_points={
       'console_scripts': [
           'etsi-asn1-decoder=etsi_asn1_decoder.decoder:main',
       ],
   },
)
