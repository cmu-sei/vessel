FROM python:3.11-bookworm

RUN apt-get update && \
  apt-get install -y \
    skopeo=1.9.3+ds1-1+b9 \
    umoci=0.4.7+ds-3+b7 \
    libmagic-dev=1:5.44-3 \
    libarchive-dev=3.6.2-1+deb12u2 \
    libarchive-tools=3.6.2-1+deb12u2 \
    sudo=1.9.13p3-1+deb12u1 \
    p7zip-full=16.02+dfsg-8 \
    r-base=4.2.2.20221110-2 \
    abootimg=0.6-1+b2 \
    apksigcopier=1.1.1-1 \
    apksigner=31.0.2-1 \
    apktool=2.7.0+dfsg-6+deb12u1 \
    db-util=5.3.2 \
    dexdump=11.0.0+r48-5 \
    docx2txt=1.4-5 \
    enjarify=1:1.0.3-5 \
    ghc=9.0.2-4 \
    caca-utils=0.99.beta20-3 \
    colord=1.4.6-2.2 \
    coreboot-utils=4.15~dfsg-3 \
    default-jdk-headless=2:1.17-74 \
    device-tree-compiler=1.6.1-4+b1 \
    ffmpeg=7:5.1.6-0+deb12u1 \
    fontforge-extras=1:20230101~dfsg-1.1~deb12u1 \
    fp-utils=3.2.2+dfsg-20 \
    genisoimage=9:1.1.11-3.4 \
    gettext=0.21-12 \
    giflib-tools=5.2.1-2.5 \
    gnumeric=1.12.55-1 \
    hdf5-tools=1.10.8+repack1-1 \
    html2text=1.3.2a-28 \
    jsbeautifier=1.14.4-1 \
    libxmlb-utils=0.3.10-2 \
    llvm=1:14.0-55.7~deb12u1 \
    lz4=1.9.4-1 \
    lzip=1.23-5 \
    mono-utils=6.8.0.105+dfsg-3.3 \
    ocaml-nox=4.13.1-4 \
    odt2txt=0.5-7 \
    oggvideotools=0.9.1-6 \
    pgpdump=0.34-1 \
    poppler-utils=22.12.0-2+b1 \
    procyon-decompiler=0.6.0-1 \
    python3-pdfminer=20221105+dfsg-1 \
    sng=1.1.0-4 \
    sqlite3=3.40.1-2+deb12u1 \
    u-boot-tools=2023.01+dfsg-2+deb12u1 \
    tcpdump=4.99.3-1 \
    wabt=1.0.32-1 \
    xxd=2:9.0.1378-2 \
    xmlbeans=4.0.0-2 \
    xxd=2:9.0.1378-2 \
    python3-guestfs=1:1.48.6-2  \
    ca-certificates

# Set up certificates for any proxies that can get in the middle of curl/wget commands during the build
# NOTE: put any CA certificates needed for a proxy in the ./certs folder in the root of this repo, in PEM format
# but with a .crt extensions, so they can be loaded into the container and used for SSL connections properly.
RUN mkdir /certs
COPY ./certs/ /certs/
RUN if [ -n "$(ls -A /certs/*.crt)" ]; then \
      cp -rf /certs/*.crt /usr/local/share/ca-certificates/; \
      update-ca-certificates; \
    fi

RUN git clone https://github.com/radareorg/radare2.git \
  && cd radare2 \
  && ./sys/install.sh \
  && rm -rf /radare2

ENV WORKDIR=/opt/project
WORKDIR ${WORKDIR}

ENV VENV_PATH="${WORKDIR}/.venv"
ENV PATH="${VENV_PATH}/bin:$PATH"

# Install poetry and set up venv. 
RUN python -m venv ${VENV_PATH} \
  && python -m pip install poetry==1.8.2

COPY ./pyproject.toml ./poetry.lock ./README.md ${WORKDIR}

# Install Python dependencies.
RUN poetry install -vv --no-cache --no-root --no-interaction --with extra_dependencies \
    && rm -rf /root/.cache/pypoetry/*

# Copy our app.
COPY ./vessel ${WORKDIR}/vessel  

# Install Vessel itself.
RUN poetry install -vv --no-cache --only-root --no-interaction \
    && rm -rf /root/.cache/pypoetry/*

ENTRYPOINT ["poetry", "run", "vessel"]
CMD ["--help"]
