package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
)

type Request struct {
	ID         int
	Method     string
	URL        string
	GetParams  map[string]string
	PostParams map[string]string
	Headers    map[string]string
	Cookies    map[string]string
	Body       string
}

type Response struct {
	ID        int
	Code      int
	Message   string
	Headers   map[string]string
	Body      string
	IDRequest int
	IsBase64  bool
}

type Repository interface {
	GetByID(id int) (bool, *Request, error)
	GetListOfRequests() ([]Request, error)
	WriteRequest(request *Request) error
	WriteResponse(response *Response) error
}

type RepositoryService struct {
	db *sql.DB
}

func NewRepositoryService(db *sql.DB) Repository {
	return &RepositoryService{db: db}
}

func (r *RepositoryService) GetByID(id int) (bool, *Request, error) {
	row := r.db.QueryRow(
		`SELECT id, method, url, get_params, post_params, headers, cookies, body FROM requests WHERE id = $1`, id)

	req := &Request{
		GetParams:  make(map[string]string),
		PostParams: make(map[string]string),
		Headers:    make(map[string]string),
		Cookies:    make(map[string]string),
	}

	var getParams, postParams, headers, cookies []byte

	err := row.Scan(
		&req.ID,
		&req.Method,
		&req.URL,
		&getParams,
		&postParams,
		&headers,
		&cookies,
		&req.Body,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil {
		log.Println(err.Error())
		return false, nil, err
	}

	json.Unmarshal(getParams, &req.GetParams)
	json.Unmarshal(postParams, &req.PostParams)
	json.Unmarshal(headers, &req.Headers)
	json.Unmarshal(cookies, &req.Cookies)

	return true, req, nil
}

func (r *RepositoryService) GetListOfRequests() ([]Request, error) {
	rows, err := r.db.Query(
		`SELECT id, method, url FROM requests ORDER BY id DESC`)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	defer rows.Close()

	var requests []Request
	for rows.Next() {
		var req Request
		if err := rows.Scan(&req.ID, &req.Method, &req.URL); err != nil {
			log.Println(err.Error())
			continue
		}
		requests = append(requests, req)
	}
	return requests, nil
}

func (r *RepositoryService) WriteRequest(request *Request) error {
	getParams, _ := json.Marshal(request.GetParams)
	postParams, _ := json.Marshal(request.PostParams)
	headers, _ := json.Marshal(request.Headers)
	cookies, _ := json.Marshal(request.Cookies)

	row := r.db.QueryRow(
		`INSERT INTO requests (method, url, get_params, post_params, headers, cookies, body) 
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		request.Method,
		request.URL,
		getParams,
		postParams,
		headers,
		cookies,
		request.Body,
	)

	if err := row.Scan(&request.ID); err != nil {
		log.Println(err.Error())
		return err
	}
	log.Println("request with id", request.ID, "was uploaded")
	return nil
}

func (r *RepositoryService) WriteResponse(response *Response) error {
	headers, _ := json.Marshal(response.Headers)

	_, err := r.db.Exec(
		`INSERT INTO responses (code, message, headers, body, req_id, is_base64) 
		VALUES ($1, $2, $3, $4, $5, $6)`,
		response.Code,
		response.Message,
		headers,
		response.Body,
		response.IDRequest,
		response.IsBase64,
	)

	if err != nil {
		//fmt.Println("RESPONSE", response.Code, response.Message, headers, response.Body, response.IDRequest)

		log.Println("\n\n\nERROR\n\n\n")
		log.Println(err.Error())
		return err
	}
	log.Println("response with req_id", response.IDRequest, "was uploaded")
	return nil
}
