import os
import sys
import time
import uuid
import json
import random
import logging
import asyncio
import argparse
from quart import Quart, request, jsonify
from camoufox.async_api import AsyncCamoufox
from patchright.async_api import async_playwright
from playwright.sync_api import sync_playwright
from playwright_recaptcha import recaptchav2

COLORS = {
    'MAGENTA': '\033[35m',
    'BLUE': '\033[34m',
    'GREEN': '\033[32m',
    'YELLOW': '\033[33m',
    'RED': '\033[31m',
    'RESET': '\033[0m',
}


class CustomLogger(logging.Logger):
    @staticmethod
    def format_message(level, color, message):
        timestamp = time.strftime('%H:%M:%S')
        return f"[{timestamp}] [{COLORS.get(color)}{level}{COLORS.get('RESET')}] -> {message}"

    def debug(self, message, *args, **kwargs):
        super().debug(self.format_message('DEBUG', 'MAGENTA', message), *args, **kwargs)

    def info(self, message, *args, **kwargs):
        super().info(self.format_message('INFO', 'BLUE', message), *args, **kwargs)

    def success(self, message, *args, **kwargs):
        super().info(self.format_message('SUCCESS', 'GREEN', message), *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        super().warning(self.format_message('WARNING', 'YELLOW', message), *args, **kwargs)

    def error(self, message, *args, **kwargs):
        super().error(self.format_message('ERROR', 'RED', message), *args, **kwargs)


logging.setLoggerClass(CustomLogger)
logger = logging.getLogger("ReCaptchaAPIServer")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)


class ReCaptchaAPIServer:
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
  <head>
    <script src="https://www.google.com/recaptcha/enterprise.js" async defer></script>
  </head>
  <body>
      <!-- recaptcha div --> 	
  </body>
</html>
    """

    def __init__(self, headless: bool, useragent: str, debug: bool, browser_type: str, thread: int, proxy_support: bool):
        self.app = Quart(__name__)
        self.debug = debug
        self.results = self._load_results()
        self.browser_type = browser_type
        self.headless = headless
        self.useragent = useragent
        self.thread_count = thread
        self.proxy_support = proxy_support
        self.browser_pool = asyncio.Queue()
        self.browser_args = []

        if useragent:
            self.browser_args.append(f"--user-agent={useragent}")

        self._setup_routes()

    @staticmethod
    def _load_results():
        """Load previous results from results.json."""
        try:
            if os.path.exists("results.json"):
                with open("results.json", "r") as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Error loading results: {str(e)}. Starting with an empty results dictionary.")
        return {}

    def _save_results(self):
        """Save results to results.json."""
        try:
            with open("results.json", "w") as result_file:
                json.dump(self.results, result_file, indent=4)
        except IOError as e:
            logger.error(f"Error saving results to file: {str(e)}")

    def _setup_routes(self) -> None:
        """Set up the application routes."""
        self.app.before_serving(self._startup)
        self.app.route('/recaptcha', methods=['GET'])(self.process_recaptcha)
        self.app.route('/result', methods=['GET'])(self.get_result)
        self.app.route('/')(self.index)

    async def _startup(self) -> None:
        """Initialize the browser and page pool on startup."""
        logger.info("Starting browser initialization")
        try:
            await self._initialize_browser()
        except Exception as e:
            logger.error(f"Failed to initialize browser: {str(e)}")
            raise

    async def _initialize_browser(self) -> None:
        """Initialize the browser and create the page pool."""

        if self.browser_type in ['chromium', 'chrome', 'msedge']:
            playwright = await async_playwright().start()
        elif self.browser_type == "camoufox":
            camoufox = AsyncCamoufox(headless=self.headless)

        for _ in range(self.thread_count):
            if self.browser_type in ['chromium', 'chrome', 'msedge']:
                browser = await playwright.chromium.launch(
                    channel=self.browser_type,
                    headless=self.headless,
                    args=self.browser_args
                )

            elif self.browser_type == "camoufox":
                browser = await camoufox.start()

            await self.browser_pool.put((_+1, browser))

            if self.debug:
                logger.success(f"Browser {_ + 1} initialized successfully")

        logger.success(f"Browser pool initialized with {self.browser_pool.qsize()} browsers")


    async def _solve_recaptcha(self, task_id: str, url: str, sitekey: str, action: str = "verify", min_score: str = "3.0", invisible: str = "0", enterprise: str = "0", data_s: str = None):
        """Solve the reCAPTCHA challenge."""
        proxy = None

        index, browser = await self.browser_pool.get()

        if self.proxy_support:
            proxy_file_path = os.path.join(os.getcwd(), "proxies.txt")

            with open(proxy_file_path) as proxy_file:
                proxies = [line.strip() for line in proxy_file if line.strip()]

            proxy = random.choice(proxies) if proxies else None

            if proxy:
                parts = proxy.split(':')
                if len(parts) == 3:
                    context = await browser.new_context(proxy={"server": f"{proxy}"})
                elif len(parts) == 5:
                    proxy_scheme, proxy_ip, proxy_port, proxy_user, proxy_pass = parts
                    context = await browser.new_context(proxy={"server": f"{proxy_scheme}://{proxy_ip}:{proxy_port}", "username": proxy_user, "password": proxy_pass})
                else:
                    raise ValueError("Invalid proxy format")
            else:
                context = await browser.new_context()
        else:
            context = await browser.new_context()

        page = await context.new_page()

        start_time = time.time()

        try:
            logger.debug(f"Browser {index}: Starting reCAPTCHA solve for URL: {url} with Sitekey: {sitekey} | Proxy: {proxy}")
            logger.debug(f"Browser {index}: Setting up page data and route..")

            url_with_slash = url + "/" if not url.endswith("/") else url

            recaptcha_div = f'<div class="g-recaptcha" data-sitekey="{sitekey}"></div>'
            page_data = self.HTML_TEMPLATE.replace("<!-- recaptcha div -->", recaptcha_div)
       
            await page.route(url_with_slash, lambda route: route.fulfill(body=page_data, status=200))
            await page.goto(url_with_slash)

            async with recaptchav2.AsyncSolver(page) as solver:
                elapsed_time = round(time.time() - start_time, 3)
                token = await solver.solve_recaptcha(wait=True)
                logger.success(f"Browser {index}: Successfully solved recaptcha in {elapsed_time} seconds")
                self.results[task_id] = {"value": token, "elapsed_time": elapsed_time}
                self._save_results()
        except Exception as e:
            elapsed_time = round(time.time() - start_time, 3)
            self.results[task_id] = {"value": "CAPTCHA_FAIL", "elapsed_time": elapsed_time}
            logger.error(f"Browser {index}: Error solving reCAPTCHA: {str(e)}")
        finally:
            if self.debug:
                logger.debug(f"Browser {index}: Clearing page state")

            await context.close()
            await self.browser_pool.put((index, browser))

    async def process_recaptcha(self):
        """Handle the /reCAPTCHA endpoint requests."""
        url = request.args.get('url')
        sitekey = request.args.get('sitekey')
        action = request.args.get('action')
        min_score = request.args.get('min_score')
        invisible = request.args.get('invisible')
        enterprise = request.args.get('enterprise')
        data_s = request.args.get('data-s')
        
        if not url or not sitekey:
            return jsonify({
                "status": "error",
                "error": "Both 'url' and 'sitekey' are required"
            }), 400

        task_id = str(uuid.uuid4())
        self.results[task_id] = "CAPTCHA_NOT_READY"

        try:
            asyncio.create_task(self._solve_recaptcha(task_id=task_id, url=url, sitekey=sitekey, action=action, min_score=min_score, invisible=invisible, enterprise=enterprise, data_s=data_s))

            if self.debug:
                logger.debug(f"Request completed with taskid {task_id}.")
            return jsonify({"task_id": task_id}), 202
        except Exception as e:
            logger.error(f"Unexpected error processing request: {str(e)}")
            return jsonify({
                "status": "error",
                "error": str(e)
            }), 500

    async def get_result(self):
        """Return solved data"""
        task_id = request.args.get('id')

        if not task_id or task_id not in self.results:
            return jsonify({"status": "error", "error": "Invalid task ID/Request parameter"}), 400

        result = self.results[task_id]
        status_code = 200

        if "CAPTCHA_FAIL" in result:
            status_code = 422

        return result, status_code

    @staticmethod
    async def index():
        """Serve the API documentation page."""
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>reCAPTCHA Solver API</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-900 text-gray-200 min-h-screen flex items-center justify-center">
                <div class="bg-gray-800 p-8 rounded-lg shadow-md max-w-2xl w-full border border-red-500">
                    <h1 class="text-3xl font-bold mb-6 text-center text-red-500">Welcome to reCAPTCHA Solver API</h1>

                    <p class="mb-4 text-gray-300">To use the reCAPTCHA service, send a GET request to 
                       <code class="bg-red-700 text-white px-2 py-1 rounded">/recaptcha</code> with the following query parameters:</p>

                    <ul class="list-disc pl-6 mb-6 text-gray-300">
                        <li><strong>url</strong>: The URL where reCAPTCHA is to be validated</li>
                        <li><strong>sitekey</strong>: The site key for reCAPTCHA</li>
                    </ul>

                    <div class="bg-gray-700 p-4 rounded-lg mb-6 border border-red-500">
                        <p class="font-semibold mb-2 text-red-400">Example usage:</p>
                        <code class="text-sm break-all text-red-300">/recaptcha?url=https://example.com&sitekey=sitekey</code>
                    </div>

                    <div class="bg-red-900 border-l-4 border-red-600 p-4 mb-6">
                        <p class="text-red-200 font-semibold">This project is inspired by 
                           <a href="https://github.com/Body-Alhoha/turnaround" class="text-red-300 hover:underline">Turnaround</a> 
                           and is currently maintained by 
                           <a href="https://github.com/Theyka" class="text-red-300 hover:underline">Theyka</a> 
                           and <a href="https://github.com/sexfrance" class="text-red-300 hover:underline">Sexfrance</a>.</p>
                    </div>
                </div>
            </body>
            </html>
        """


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="reCAPTCHA API Server")

    parser.add_argument('--headless', type=bool, default=False, help='Run the browser in headless mode, without opening a graphical interface. This option requires the --useragent argument to be set (default: False)')
    parser.add_argument('--useragent', type=str, default="Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1a2pre) Gecko/2008073000 Shredder/3.0a2pre ThunderBrowse/3.2.1.8", help='Specify a custom User-Agent string for the browser. If not provided, the default User-Agent is used')
    parser.add_argument('--debug', type=bool, default=True, help='Enable or disable debug mode for additional logging and troubleshooting information (default: False)')
    parser.add_argument('--browser_type', type=str, default='chrome', help='Specify the browser type for the solver. Supported options: chromium, chrome, msedge, camoufox (default: chromium)')
    parser.add_argument('--thread', type=int, default=1, help='Set the number of browser threads to use for multi-threaded mode. Increasing this will speed up execution but requires more resources (default: 1)')
    parser.add_argument('--proxy', type=bool, default=False, help='Enable proxy support for the solver (Default: False)')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='Specify the IP address where the API solver runs. (Default: 127.0.0.1')
    parser.add_argument('--port', type=str, default='8000', help='Set the port for the API solver to listen on. (Default: 8000)')
    return parser.parse_args()


def create_app(headless: bool, useragent: str, debug: bool, browser_type: str, thread: int, proxy_support: bool) -> Quart:
    server = ReCaptchaAPIServer(headless=headless, useragent=useragent, debug=debug, browser_type=browser_type, thread=thread, proxy_support=proxy_support)
    return server.app


if __name__ == '__main__':
    args = parse_args()
    browser_types = [
        'chromium',
        'chrome',
        'msedge',
        'camoufox',
    ]
    if args.browser_type not in browser_types:
        logger.error(f"Unknown browser type: {COLORS.get('RED')}{args.browser_type}{COLORS.get('RESET')} Available browser types: {browser_types}")
    elif args.headless is True and args.useragent is None and "camoufox" not in args.browser_type:
        logger.error(f"You must specify a {COLORS.get('YELLOW')}User-Agent{COLORS.get('RESET')} for reCAPTCHA Solver or use {COLORS.get('GREEN')}camoufox{COLORS.get('RESET')} without useragent")
    else:
        app = create_app(headless=args.headless, debug=args.debug, useragent=args.useragent, browser_type=args.browser_type, thread=args.thread, proxy_support=args.proxy)
        app.run(host=args.host, port=int(args.port))
