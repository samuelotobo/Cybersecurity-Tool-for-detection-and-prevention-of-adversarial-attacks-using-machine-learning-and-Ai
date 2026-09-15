from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs
datas    = collect_data_files('PyQt6')
binaries = collect_dynamic_libs('PyQt6')
