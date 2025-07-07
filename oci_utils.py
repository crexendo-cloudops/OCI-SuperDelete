import oci
import argparse
import sys
import subprocess
import os
import logging
import pexpect
from typing import Optional, Type, TypeVar
from oci.exceptions import ServiceError

# Set up logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

T = TypeVar('T')

def get_common_parser(description: str) -> argparse.ArgumentParser:
    """
    Get an argument parser with common OCI arguments.
    """
    logger.debug(f"Creating argument parser with description: {description}")
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--profile', default="DEFAULT", help='OCI profile to use for authentication')
    parser.add_argument('--region', default="us-phoenix-1", help='OCI region to use')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    return parser

def _is_token_valid(profile: str, debug: bool = False) -> bool:
    """Check if a security token is valid using oci session validate"""
    if debug:
        logger.setLevel(logging.DEBUG)
    logger.debug(f"Checking token validity for profile: {profile}")
    try:
        config_file = os.path.expanduser("~/.oci/config")
        logger.debug(f"Using config file: {config_file}")
        
        cmd = f'oci session validate --config-file {config_file} --profile {profile} --auth security_token'
        logger.debug(f"Running command: {cmd}")
        
        # Use pexpect to handle the interactive prompt
        child = pexpect.spawn(cmd)
        try:
            # Wait for either the prompt or the command to complete
            index = child.expect([r'Do you want to re-authenticate your CLI session profile\? \[Y/n\]:', 
                                'Session is valid until',
                                'ERROR: This CLI session has expired',
                                pexpect.EOF],
                               timeout=10)  # Add a reasonable timeout
            
            if index == 0 or index == 2:
                # Session expired or needs re-authentication
                logger.debug("Session expired or needs re-authentication")
                child.sendline('n')  # Don't re-authenticate here, let the main flow handle it
                child.expect(pexpect.EOF)
                return False
            elif index == 1:
                # Session is valid
                logger.debug("Session is valid")
                child.expect(pexpect.EOF)
                child.close()
                return True
            else:
                # Command completed without expected output
                logger.debug("Command completed without expected output")
                child.close()
                return False
        except pexpect.TIMEOUT:
            logger.error("Timeout waiting for command response")
            child.close()
            return False
        except pexpect.EOF:
            logger.debug("Command completed with EOF")
            child.close()
            return False
    except Exception as e:
        logger.error(f"Error checking token validity: {str(e)}")
        return False

def _get_client_with_browser_auth(client_class: Type[T], profile: str, region: str, debug: bool = False) -> T:
    """Helper function to get a client using browser-based authentication"""
    if debug:
        logger.setLevel(logging.DEBUG)
    logger.debug(f"Starting browser-based authentication for profile: {profile}")
    
    try:
        # Get the OCI config file path
        config_file = os.path.expanduser("~/.oci/config")
        logger.debug(f"Using config file: {config_file}")
        config = oci.config.from_file(profile_name=profile)
        
        # First check if we have a valid security token for this profile
        logger.debug("Checking for existing valid token...")
        if _is_token_valid(profile, debug):
            logger.debug("Using existing security token")
            
            # Load the token file
            token_file = config['security_token_file']
            logger.debug(f"Loading token from: {token_file}")
            with open(token_file, 'r') as f:
                token = f.read()
            
            # Load the private key
            private_key = oci.signer.load_private_key_from_file(config['key_file'])
            
            # Create the security token signer
            signer = oci.auth.signers.SecurityTokenSigner(token, private_key)
            
            # Create the client with the security token signer
            return client_class({'region': region}, signer=signer)
        
        # If no valid token exists, create a new one
        logger.debug("No valid token found, starting new authentication")
        logger.debug(f"Using region: {region}")
        
        # Notify user that browser authentication will start
        print("\nBrowser authentication required. A browser window will open shortly...\n", file=sys.stderr)
        
        # Use pexpect to handle the authentication process
        cmd = f'oci session authenticate --config-file {config_file} --profile {profile} --region {region}'
        logger.debug(f"Running authentication command: {cmd}")
        
        child = pexpect.spawn(cmd)
        try:
            # Wait for the profile name prompt
            child.expect('Enter the name of the profile you would like to create:')
            # Send the profile name
            child.sendline(profile)
            # Wait for the command to complete
            child.expect(pexpect.EOF)
            child.close()
            
            if child.exitstatus != 0:
                raise subprocess.CalledProcessError(child.exitstatus, cmd)
            
            logger.debug("Authentication command completed")
            
            # Create a new config with the security token
            logger.debug("Creating new client with security token")
            
            # Load the token file
            token_file = config['security_token_file']
            logger.debug(f"Loading token from: {token_file}")
            with open(token_file, 'r') as f:
                token = f.read()
            
            # Load the private key
            private_key = oci.signer.load_private_key_from_file(config['key_file'])
            
            # Create the security token signer
            signer = oci.auth.signers.SecurityTokenSigner(token, private_key)
            
            # Create the client with the security token signer
            return client_class({'region': region}, signer=signer)
        except pexpect.TIMEOUT:
            logger.error("Timeout during authentication")
            child.close()
            raise
    except subprocess.CalledProcessError as e:
        logger.error(f"Error during OCI CLI authentication: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during browser auth: {str(e)}")
        sys.exit(1)

def get_authenticated_client(client_class: Type[T], profile: str, region: Optional[str] = None, debug: bool = False) -> T:
    """
    Get an authenticated OCI client instance using the SDK's built-in authentication.
    If authentication fails, it will attempt to use browser-based authentication.
    
    Args:
        client_class: The OCI client class to instantiate
        profile: The OCI profile name to use
        region: Optional region to use. If not provided, will use the region from the config file
        debug: Whether to enable debug logging
    """
    if debug:
        logger.setLevel(logging.DEBUG)
    logger.debug(f"Getting authenticated client for profile: {profile}")
    
    try:
        # First try the standard authentication
        logger.debug("Attempting standard authentication")
        config = oci.config.from_file(profile_name=profile)
        
        # Use provided region or fall back to config file region
        effective_region = region or config.get('region')
        if not effective_region:
            effective_region = "us-phoenix-1"  # Fallback to default if no region in config
        logger.debug(f"Using region: {effective_region}")
        
        # Try to load the token file if it exists
        if 'security_token_file' in config:
            logger.debug("Found security token file, attempting to use it")
            try:
                # Load the token file
                token_file = config['security_token_file']
                logger.debug(f"Loading token from: {token_file}")
                with open(token_file, 'r') as f:
                    token = f.read()
                
                # Load the private key
                private_key = oci.signer.load_private_key_from_file(config['key_file'])
                
                # Create the security token signer
                signer = oci.auth.signers.SecurityTokenSigner(token, private_key)
                
                # Create the client with the security token signer
                client = client_class({'region': effective_region}, signer=signer)
                
                # Test the authentication
                if hasattr(client, 'get_tenancy'):
                    try:
                        client.get_tenancy(config['tenancy'])
                        logger.debug("Security token authentication successful")
                        return client
                    except ServiceError as e:
                        if e.status == 401:
                            logger.debug("Security token authentication failed (401), trying browser auth")
                            return _get_client_with_browser_auth(client_class, profile, effective_region, debug)
                        raise
            except Exception as e:
                logger.debug(f"Error using security token: {str(e)}, trying browser auth")
                return _get_client_with_browser_auth(client_class, profile, effective_region, debug)
        
        # If no security token, try standard authentication
        client = client_class(config)
        
        # Try a simple API call to verify authentication
        if hasattr(client, 'get_tenancy'):
            try:
                client.get_tenancy(config['tenancy'])
                logger.debug("Standard authentication successful")
                return client
            except ServiceError as e:
                if e.status == 401:
                    logger.debug("Standard authentication failed (401), trying browser auth")
                    return _get_client_with_browser_auth(client_class, profile, effective_region, debug)
                logger.error(f"Service error during authentication: {str(e)}")
                raise
        return client
    except Exception as e:
        logger.error(f"Error creating OCI client: {str(e)}")
        sys.exit(1) 