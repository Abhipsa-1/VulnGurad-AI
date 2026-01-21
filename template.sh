#!/bin/bash

project_name="cnnClassifier"

files=(
    ".github/workflows/.gitkeep"
    "src/$project_name/__init__.py"
    "src/$project_name/components/__init__.py"
    "src/$project_name/components/stage__00_data_ingestion.py"
    "src/$project_name/components/stage__01_data_validation.py"
    "src/$project_name/components/stage__02_data_transformation.py"
    "src/$project_name/components/stage__03_model_trainer.py"
    "src/$project_name/utils/__init__.py"
    "src/$project_name/utils/util.py"
    "src/$project_name/config/__init__.py"
    "src/$project_name/config/configuration.py"
    "src/$project_name/pipeline/__init__.py"
    "src/$project_name/pipeline/training_pipeline.py"
    "src/$project_name/entity/__init__.py"
    "src/$project_name/entity/config_entity.py"
    "src/$project_name/constants/__init__.py"
    "src/$project_name/logger/__init__.py"
    "src/$project_name/logger/log.py"
    "src/$project_name/exception/__init__.py"
    "src/$project_name/exception/exception_handler.py"
    "config/config.yaml"
    "dvc.yaml"
    "app.py"
    "params.yaml"
    "requirements.txt"
    "setup.py"
    "research/trials.ipynb"
    "templates/index.html"
)

echo "Starting project structure creation..."

for filepath in "${files[@]}"; do
    dir=$(dirname "$filepath")
    filename=$(basename "$filepath")

    # Create directory if not empty
    if [[ "$dir" != "." ]]; then
        mkdir -p "$dir"
        echo "Creating directory: $dir for file: $filename"
    fi

    # Create file if not exists or empty
    if [[ ! -f "$filepath" || ! -s "$filepath" ]]; then
        touch "$filepath"
        echo "Creating empty file: $filepath"
    else
        echo "$filename already exists"
    fi

done

echo "All files and directories created!"
