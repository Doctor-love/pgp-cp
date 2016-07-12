#!/usr/bin/env python

'''pgp-cp - Copies file to destination if PGP signature is trusted'''

description = __doc__
developers = ['Joel Rangsmo <joel@rangsmo.se>']
license = 'GPLv3'
version = '0.3.1'

try:
    import os
    import json
    import gnupg
    import shutil
    import logging
    import argparse

    from sys import exit

except ImportError as error_msg:
    print('Failed to import dependencies: "%s"' % error_msg)
    exit(3)

logger = logging.getLogger('pgp-cp')

# -----------------------------------------------------------------------------

def parse_args():
    '''Parses commandline arguments provided by the user'''

    parser = argparse.ArgumentParser(
        description=description,
        epilog=(
            'Developed by %s - licensed under %s!'
            % (', '.join(developers), license)))

    parser.add_argument(
        '-i', '--input', dest='input_path',
        help='Path to input file',
        metavar='/path/to/input_file', type=str, required=True)

    parser.add_argument(
        '-s', '--sig', dest='sig_path',
        help='Path to input file signature',
        metavar='/path/to/input_file.sig', type=str, required=True)

    parser.add_argument(
        '-o', '--output', dest='output_path',
        help='Path to target output file',
        metavar='/path/to/output_file', type=str, required=True)
    
    parser.add_argument(
        '-t', '--trust-level', dest='required_trust_level',
        help='Required trust level of file signature (default: %(default)i)',
        choices=[2, 3, 4], type=int, default=3)
    
    parser.add_argument(
        '-q', '--quar', dest='quar_dir',
        help='Path to file quarantine directory (default: %(default)s)',
        metavar='/path/to/quar_dir', type=str, default='~/pgp-cp_quar')

    parser.add_argument(
        '-g', '--gpg-home',
        help='Path to GnuPG home directory (default: %(default)s)',
        metavar='~/.gnupg', type=str, default='~/.gnupg')
    
    parser.add_argument(
        '-l', '--log-dest',
        help='Set application logging destination (default: %(default)s)',
        choices=('stream', 'syslog', 'none'), default='stream')

    parser.add_argument(
        '-v', '--verbose', dest='log_verbose',
        action='store_true', default=False,
        help='Enable verbose application logging')
    
    parser.add_argument(
        '-V', '--version',
        help='Shows application version',
        action='version', version=version)

    return parser.parse_args()

# -----------------------------------------------------------------------------

class CustomNullHandler(logging.Handler):
    '''Custom null handler for logging, since it isn\'t available in 2.6'''

    def emit(self, record):
        pass


def log_init(destination, verbose):
    '''Configures application logging'''

    global logger
    
    formatter = logging.Formatter('pgp-cp: %(levelname)s - %(message)s')

    if verbose:
        logger.setLevel(logging.DEBUG)

        gnupg_logger = logging.getLogger('gnupg')
        gnupg_logger.setLevel(logging.DEBUG)

    else:
        logger.setLevel(logging.INFO)

    if destination == 'stream':
        log_handler = logging.StreamHandler()

    elif destination == 'syslog':
        log_handler = logging.handlers.SysLogHandler(address='/dev/log')

    elif destination == 'none':
        log_handler = CustomNullHandler()

    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)

    if verbose:
        gnupg_logger.addHandler(log_handler)

    return

# -----------------------------------------------------------------------------

def main():
    '''Main application function'''

    args = parse_args()
    log_init(args.log_dest, args.log_verbose)
    
    logger.debug(
        'Application started by user ID "%i" with arguments: "%s"'
        % (os.getuid(), str(args)))

    # -------------------------------------------------------------------------
    logger.debug('Creating GnuPG instance with home "%s"' % args.gpg_home)

    try:
        gpg = gnupg.GPG(homedir=args.gpg_home)

    except Exception as error_msg:
        logger.error('Failed to initialize GnuPG: "%s"' % error_msg)
        exit(1)
    
    # -------------------------------------------------------------------------
    logger.debug('Setting up quarantine directory in "%s"' % args.quar_dir)

    try:
        quar_dir = os.path.expanduser(args.quar_dir)

        if not os.path.exists(quar_dir):
            logger.info('Creating quarantine directory "%s"' % args.quar_dir)

            os.mkdir(quar_dir)

        logger.info(
            'Copying input file "%s" and signature "%s" to quarantine "%s"'
            % (args.input_path, args.sig_path, args.quar_dir))

        shutil.copy(args.input_path, quar_dir)
        shutil.copy(args.sig_path, quar_dir)
        
        logger.debug('Building new file paths for input')

        input_path = os.path.join(
            quar_dir, os.path.basename(args.input_path))
        
        sig_path = os.path.join(
            quar_dir, os.path.basename(args.sig_path))

    except Exception as error_msg:
        logger.error(
            'Failed to quaratine input file "%s" in "%s": "%s"'
            % (args.input_path, args.quar_dir, error_msg))

        exit(1)

    # -------------------------------------------------------------------------
    logger.info('Loading signed input file from "%s"' % input_path)

    try:
        input_data = gpg.verify_file(open(input_path), sig_file=sig_path)

    except Exception as error_msg:
        logger.error('Failed to open input file: "%s"' % error_msg)
        exit(1)

    # -------------------------------------------------------------------------
    logger.info('Verifying signature of input file against trust database')

    if not input_data.valid:
        logger.error('Signature of file "%s" is not valid' % input_path)
        exit(1)

    logger.info(
        'Sinature was signed at "%s" by "%s" with key ID "%s"'
        % (input_data.creation_date, input_data.username, input_data.key_id))

    if input_data.trust_level < args.required_trust_level:
        logger.error(
            'Trust level "%i" of signature did not meet specified requirements'
            % (input_data.trust_level))

        exit(2)

    else:
        logger.debug('Trust level of signature: "%i"' % input_data.trust_level)
    
    # -------------------------------------------------------------------------
    logger.info(
        'Moving quarantined file "%s" to output target "%s"'
        % (input_path, args.output_path))

    try:
        shutil.move(input_path, args.output_path)
        os.remove(sig_path)

    except Exception as error_msg:
        logger.error(
            'Failed to create file "%s": "%s"' % (args.output_path, error_msg))

        exit(1)

    logger.info(
        'Successfully copied input file "%s" to output file "%s"'
        % (args.input_path, args.output_path))

    exit(0)


if __name__ == '__main__':
    main()
