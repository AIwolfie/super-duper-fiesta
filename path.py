from webdriver_manager.chrome import ChromeDriverManager

chrome_driver_path = ChromeDriverManager().install()
print("ChromeDriver Path:", chrome_driver_path)
