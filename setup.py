from setuptools import setup

setup(
    name='etsi-asn1-decoder',
    version='0.1.0',
    description='Smart ASN.1 DER Decoder for ETSI Specs',
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
