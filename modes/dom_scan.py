import asyncio
import json
import os
import sys
import argparse
from typing import List, Dict, Optional
from core.dom_detector import DOMDetector
from core.payload_engine import payload_engine
from core.log import setup_logger

logger = setup_logger(__name__)

async def dom_scan(
    url: str,
    param_name: Optional[str] = None,
    param_value: Optional[str] = None,
    payloads: Optional[List[str]] = None,
    headless: bool = True,
    screenshot_dir: Optional[str] = None,
    output_file: Optional[str] = None
):
    """
    Perform DOM-based XSS scanning.
    
    Args:
        url: Target URL
        param_name: Parameter name to inject into
        param_value: Original parameter value
        payloads: List of payloads to try
        headless: Whether to run browser in headless mode
        screenshot_dir: Directory to save screenshots
        output_file: File to save results to
    """
    # Initialize the DOM detector
    detector = DOMDetector(headless=headless, screenshot_dir=screenshot_dir)
    await detector.initialize()
    
    try:
        # If no payloads provided, use the payload engine
        if not payloads:
            payloads = payload_engine.get_all_payloads()
        
        results = []
        
        # First, analyze the page without injection
        logger.info(f"Analyzing page: {url}")
        analysis = await detector.analyze_page(url)
        results.append({
            "type": "initial_analysis",
            "data": analysis
        })
        
        # If parameter is specified, inject payloads
        if param_name and param_value:
            logger.info(f"Injecting payloads into parameter: {param_name}")
            
            # Try each payload
            for context, context_payloads in payloads.items():
                logger.info(f"Trying {len(context_payloads)} payloads for context: {context}")
                
                for payload in context_payloads:
                    logger.info(f"Trying payload: {payload}")
                    
                    # Inject the payload
                    injection_result = await detector.inject_payload(
                        url=url,
                        payload=payload,
                        param_name=param_name,
                        param_value=param_value
                    )
                    
                    # Add to results
                    results.append({
                        "type": "payload_injection",
                        "context": context,
                        "data": injection_result
                    })
                    
                    # If XSS detected, log it
                    if injection_result.get("dialogs") or injection_result.get("dangerous_operations"):
                        logger.warning(f"Potential XSS detected with payload: {payload}")
                        logger.warning(f"Dialogs: {injection_result.get('dialogs')}")
                        logger.warning(f"Dangerous operations: {injection_result.get('dangerous_operations')}")
        
        # Save results if output file specified
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results saved to: {output_file}")
        
        return results
        
    finally:
        # Clean up
        await detector.close()

def main():
    """
    Main entry point for DOM scanning.
    """
    parser = argparse.ArgumentParser(description="DOM-based XSS scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--param", help="Parameter name to inject into")
    parser.add_argument("--value", help="Original parameter value")
    parser.add_argument("--payloads", help="File containing payloads (one per line)")
    parser.add_argument("--no-headless", action="store_true", help="Run browser in non-headless mode")
    parser.add_argument("--screenshots", help="Directory to save screenshots")
    parser.add_argument("--output", help="File to save results to")
    
    args = parser.parse_args()
    
    # Load payloads if file specified
    payloads = None
    if args.payloads:
        with open(args.payloads, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
    
    # Run the scanner
    asyncio.run(dom_scan(
        url=args.url,
        param_name=args.param,
        param_value=args.value,
        payloads=payloads,
        headless=not args.no_headless,
        screenshot_dir=args.screenshots,
        output_file=args.output
    ))

if __name__ == "__main__":
    main() 