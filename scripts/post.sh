#!/bin/bash
curl -X POST -H "Content-Type: application/json" -d '{"id":"xyz","path":"abc","data":"123"}' localhost:3000/send