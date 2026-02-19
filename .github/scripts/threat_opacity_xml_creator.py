#!/usr/bin/env python3
import re
import copy
import sys
import base64
import zlib
import argparse
from urllib.parse import unquote
from pathlib import Path
from collections import defaultdict

from bs4 import BeautifulSoup as BS4

OPACITY_PERCENT = 10

def decompress(original_soup, bs4_backend='xml'):
    """
    tries to decode/decompress contents of `diagram` tag;
    prefers plain XML (most common), falls back to draw.io compressed form.

    :param original_soup BS4: BS4 object of the source file/markup
    :param bs4_backend str: backend of BS4
    """
    print("[decompress] Start")
    diagram_tag = original_soup.select_one('diagram')
    if not diagram_tag:
        print("[decompress] No <diagram> tag found")
        return

    # If the diagram already contains a parsed graph, do nothing
    if diagram_tag.find('mxGraphModel') is not None:
        print("[decompress] <diagram> already contains <mxGraphModel>; skipping")
        return

    enc_text = (diagram_tag.text or "").strip()
    if not enc_text:
        print("[decompress] <diagram> has no text")
        return

    # Helper to extract an mxGraphModel from XML text, including nested mxfile cases
    def _extract_graph(xml_text: str):
        inner = BS4(xml_text, bs4_backend)
        graph = inner.find('mxGraphModel')
        if not graph:
            graph = inner.select_one('mxfile > diagram > mxGraphModel')
            if not graph:
                # Try nested base64/deflate inside inner <mxfile><diagram>
                inner_diagram = inner.select_one('mxfile > diagram')
                if inner_diagram:
                    inner_text = (inner_diagram.text or "").strip()
                    if inner_text:
                        try:
                            dec2 = base64.b64decode(inner_text)
                            try:
                                xml2 = unquote(zlib.decompress(dec2, -zlib.MAX_WBITS).decode('utf-8'))
                            except Exception:
                                xml2 = dec2.decode('utf-8', errors='ignore')
                            inner2 = BS4(xml2, bs4_backend)
                            graph = inner2.find('mxGraphModel') or inner2.select_one('mxfile > diagram > mxGraphModel')
                        except Exception:
                            pass
        return graph

    # Step 1: base64 decode
    try:
        decoded_bytes = base64.b64decode(enc_text)
        print(f"[decompress] Base64 decoded bytes={len(decoded_bytes)}")
    except Exception:
        print("[decompress] Not base64 content; leaving as-is")
        return

    # Step 2: try plain XML first (most inputs are already uncompressed XML)
    try:
        as_text = decoded_bytes.decode('utf-8', errors='ignore')
        looks_like_xml = (
            as_text.lstrip().startswith('<')
            or '<mxGraphModel' in as_text
            or '<mxfile' in as_text
        )
        print(f"[decompress] Decoded bytes look like XML: {looks_like_xml}")
        if looks_like_xml:
            graph = _extract_graph(as_text)
            if graph:
                diagram_tag.clear()
                diagram_tag.append(graph)
                # normalise compression flags
                mxfile = original_soup.select_one('mxfile')
                if mxfile is not None:
                    mxfile['compressed'] = 'false'
                if 'compressed' in diagram_tag.attrs:
                    del diagram_tag['compressed']
                print("[decompress] Embedded mxGraphModel into <diagram> (from plain XML)")
                return
    except Exception as e:
        print(f"[decompress] Plain XML check failed: {e}")

    # Step 3: fallback to deflate (draw.io compressed form)
    try:
        decompressed_string = unquote(
            zlib.decompress(decoded_bytes, -zlib.MAX_WBITS).decode('utf-8')
        )
        graph = _extract_graph(decompressed_string)
        if graph:
            diagram_tag.clear()
            diagram_tag.append(graph)
            mxfile = original_soup.select_one('mxfile')
            if mxfile is not None:
                mxfile['compressed'] = 'false'
            if 'compressed' in diagram_tag.attrs:
                del diagram_tag['compressed']
            print("[decompress] Deflate decompression successful; embedded mxGraphModel")
            return
        else:
            print("[decompress] Deflate decompression produced XML without mxGraphModel; leaving as-is")
    except Exception as e:
        # Leave content as-is; downstream may handle it
        print(f"[decompress] Deflate decompression failed; leaving as-is: {e}")
        return


def make_validation(soup):
    """
    makes validation over formats of `feature_class` & `threat` values;
    raises an error if it doesn't pass

    :param soup BS4: default BS4 object of source file
    """
    object_tags = soup.select('object')

    # -> "threat" attribute is either:
    #   non-represent,
    #   empty,
    #   one item "FCx_Ty",
    #   a comma-seperated list of FCx_Ty,
    #   or FCx_all (where x,y are numbers)
    FCx_Ty_re = re.compile(r'^FC\d+_T\d+$')
    FCx_all_re = re.compile(r'^(FC\d+_)*all$')
    error_list = []
    
    for tag in object_tags:
        threat = tag.get('threat')
        if threat:
            threat_list = threat.strip().split(',')
            for threat_entry in threat_list:
                if not FCx_Ty_re.search(threat_entry) and not FCx_all_re.search(threat_entry):
                    error_list.append(f'Incorrect threat value: {threat}')

    # -> "feature_class" is either:
    #   non-represent,
    #   empty,
    #   one item "FCx",
    #   a comma-seperated list of FCx,
    #   or all (where x,y are numbers)
    FCx_re = re.compile(r'^((,?FC\d+)|(,?all))+$')
    for tag in object_tags:
        feature_class = tag.get('feature_class')
        if feature_class:
            feature_class = feature_class.strip()
            if not FCx_re.search(feature_class):
                error_list.append(f'Incorrect feature_class value: {feature_class}')
    
    if error_list:
        for error in error_list:
            print(error)
        sys.exit(1)

def FCx_do_hide(curr_fc_value, object_tag):
    """
    detects: should tag to be hided or not; returns bool

    :param curr_fc_value str: FCx value
    :param object_tag BS4: object tag of XML file
    """
    feature_class = [x.strip() for x in (object_tag.get('feature_class') or '').split(',') if x.strip()]
    threat_list = [x.strip() for x in (object_tag.get('threat') or '').split(',') if x.strip()]
    
    if curr_fc_value in feature_class:
        return False

    if 'all' in feature_class:
        return False

    for threat in threat_list:
        if threat == 'all':
            return False
        threat_fc_value = threat.split('_')[0]
        fc_all = '%s_all' % threat_fc_value
        if curr_fc_value == threat_fc_value or fc_all == threat:
            return False

    return True

def FCx_Ty_do_hide(curr_t_value, object_tag):
    """
    detects: should tag to be hided or not; returns bool
    (almost the same as FCx_do_hide function; take a look at it)

    :param curr_t_value str: Ty value
    :param object_tag BS4: object tag of XML file
    """
    # must be hided if there's no `threat` attr at all
    threat = object_tag.get('threat')

    if not threat:
        return True
    
    threat = [x.strip() for x in str(threat).split(',') if x.strip()]

    curr_fc_value = curr_t_value.split('_')[0]
    key2 = '%s_all' % curr_fc_value

    if curr_t_value not in threat and 'all' not in threat and key2 not in threat:
        return True

    return False


def make_tags_gray(tags):
    """
    adds textOpacity/opacity to tags to make them gray (inplace)

    :param tags list: list of BS4 objects (tags) to hide
    """
    for tag in tags:
        if tag.get('style'):
            tag['style'] += ';textOpacity={0};opacity={0};'.format(OPACITY_PERCENT)
        else:
            tag['style'] = 'textOpacity={0};opacity={0};'.format(OPACITY_PERCENT)


def generate_FCx_files(original_soup, fcx_tx_values, dest_dir, prefix_service):
    """
    generates new XML files based on an original one; makes gray objects/mxcells
    that haven't FCx value and saves new file into dest_dir

    :param original_soup BS4 object: default BS4 object of original file
    :param fcx_tx_values dict: dict of FCx/Tx values
    :param dest_dir Path: location to save the files to
    """
    output_filename_tpl = prefix_service + '_{fc_value}.xml'

    fc_value_list = []
    for fc_value in fcx_tx_values.get('FC', []):
        fc_value_list.append(fc_value)
    for t_value in fcx_tx_values.get('T', []):
        curr_fc_value = t_value.split('_')[0]
        if curr_fc_value not in fc_value_list and curr_fc_value != 'all':
            fc_value_list.append(curr_fc_value)

    for fc_value in fc_value_list:
        soup = copy.deepcopy(original_soup)

        # mx cells tags to be hided:
        #   we must include root > mxCell tags here (w/o any condition)
        mxcell_tags_to_hide = soup.select('root > mxCell')

        object_tags = soup.select('root > object')
        for object_tag in object_tags:
            if FCx_do_hide(fc_value, object_tag):
                mxcell_tags = object_tag.select('mxCell')
                mxcell_tags_to_hide.extend(mxcell_tags)

        # make gray all of them (inplace)
        make_tags_gray(mxcell_tags_to_hide)

        # and write out the data
        output_filename = dest_dir / f"{prefix_service}_{fc_value}.xml"
        with open(output_filename, 'w') as fp:
            fp.write(soup.prettify())
            print(f'Created {output_filename_tpl.format(fc_value=fc_value)}')


def generate_FCx_Ty_files(original_soup, fcx_tx_values, dest_dir, prefix_service):
    """
    generates new XML files based on an original one; makes gray objects/mxcells
    that haven't FCx_Ty values and saves new file into dest_dir

    :param original_soup BS4: BS4 object of original file
    :param dest_dir Path: firectory to save the output files to
    """
    # the new files will be generated based on these ones
    output_filename_tpl = prefix_service + '_{t_value}.xml'
    for t_value in fcx_tx_values.get('T', []):
        if 'all' in t_value:
            continue
        soup = copy.deepcopy(original_soup)

        # mx cells tags to be hided:
        #   we must include root > mxCell tags here (w/o any condition)
        mxcell_tags_to_hide = soup.select('root > mxCell')

        object_tags = soup.select('root > object')
        for object_tag in object_tags:
            if FCx_Ty_do_hide(t_value, object_tag):
                mxcell_tags = object_tag.select('mxCell')
                mxcell_tags_to_hide.extend(mxcell_tags)

        # make gray all of them (inplace)
        make_tags_gray(mxcell_tags_to_hide)

        # and write out the data
        output_filename = dest_dir / f"{prefix_service}_{t_value}.xml"
        with open(output_filename, 'w') as fp:
            fp.write(soup.prettify())
            print(f'Created {output_filename_tpl.format(t_value=t_value)}')

def get_all_FCx_Tx_values(source_soup):
    """
    returns all possible FCx & Tx values defined in source XML file (source_soup
    object)

    :param source_soup BS4: default BS4 object of source XML file
    """
    object_tags = source_soup.select('object')

    values = list()
    for tag in object_tags:
        splitted = list()

        threat = tag.get('threat')
        if threat:
            splitted = list(map(str.strip, threat.split(',')))

        feature_class = tag.get('feature_class')
        if feature_class:
            splitted += list(map(str.strip, feature_class.split(',')))

        for chunk in splitted:
            chunk = chunk if isinstance(chunk, list) else [chunk]
            values.extend(chunk)

    # now construct dict we actually need
    ret_dict = defaultdict(set)
    for v in values:
        if '_' in v:
            update_key = 'T'
        elif v == 'all':
            continue
        else:
            update_key = 'FC'
        ret_dict[update_key].add(v)

    # form of
    # {
    #     'FC': {'FC1', 'FC2', ...}
    #     'T': {'FC1_T1', 'FC3_T2', ...}
    # }
    return ret_dict


def main():
    BS4_BACKEND = 'xml'
    THIS_DIR = Path(__file__).parent

    parser = argparse.ArgumentParser(description='draw.io tool')
    parser.add_argument('input_filename', help='Source XML filename')
    parser.add_argument(
        '--threat-dir',
        default=THIS_DIR,
        help='Directory to output threat files to (default ./)',
    )
    parser.add_argument(
        '--fc-dir',
        default=THIS_DIR,
        help='Directory to output threat files to (default ./)',
    )
    parser.add_argument(
        '--validate',
        default=False,
        action='store_true',
        help='Flag indicating whether do validation or not',
    )

    args = parser.parse_args()
    src_filename = Path(args.input_filename)
    threat_dir = Path(args.threat_dir)
    fc_dir = Path(args.fc_dir)

    if not src_filename.exists():
        sys.exit(f'{src_filename} does not exist. Aborting.')
    if not src_filename.is_file():
        sys.exit(f'{src_filename} is not a file. Aborting.')

    threat_dir.mkdir(exist_ok=True)
    fc_dir.mkdir(exist_ok=True)

    soup = None
    with open(src_filename) as fp:
        soup = BS4(fp.read(), BS4_BACKEND)
    
    prefix_service = src_filename.stem
    
    # decompress it firstly (INPLACE!) (at least try)
    # if it's compressed (contents of diagram tag)
    decompress(soup, BS4_BACKEND)

    # make validation before
    if args.validate:
        make_validation(soup)

    # get all FCx/Tx values defined in the file
    fcx_tx_values = get_all_FCx_Tx_values(soup)

    # generate new ...FCx.xml files based on FCx values found
    generate_FCx_files(soup, fcx_tx_values, fc_dir, prefix_service)

    # generate new ...FCx_Ty.xml files based on FCx/Tx values found
    generate_FCx_Ty_files(soup, fcx_tx_values, threat_dir, prefix_service)


if __name__ == '__main__':
    main()
