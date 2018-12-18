#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdio>
#include <string>
#include <filesystem>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

using namespace std::filesystem;

class antivirus_scaner {
private:
    std::vector<std::string> virus_strings;

    void read_data_of_dangerous_files() {
        std::ifstream fin("C:\\Users\\Asus\\Desktop\\carantin\\data.txt");
        std::string str;

        while (std::getline(fin, str)) {
            virus_strings.push_back(str);
        }
        fin.close();
    }

    void move_file(std::string filname, std::string name) {
        const char * from, *to;
        from = filname.c_str();
        name = "C:\\Users\\Asus\\Desktop\\carantin\\" + name;
        to = name.c_str();
        rename(from, to);
    }

    void checking_dyrectory(const path & checking = "C:\\Users\\Asus\\Desktop\\kurs" ) {
        path name_of_directory = checking;
        for (const directory_entry& x : directory_iterator{ name_of_directory }) {
            if ( is_directory( x.path() ) ) {
                checking_dyrectory( x.path() );
            }
            else {
                std::string name = x.path().stem().generic_string(), extension = x.path().extension().generic_string();
                if (extension == ".exe") {
                    if (is_dangerous(x.path().generic_string())) {
                        move_file(x.path().generic_string(), x.path().filename().generic_string());
                    }
                }
            }
        }
    }

    bool checking_file(std::string & buf) {

        for (auto i : virus_strings) {
            if ( buf.find(i) != std::string::npos )
                    return true;
        }
        return false;
    }

    bool is_dangerous(std::string name) {
        bool succsess = false;
        std::ifstream ifile(name, std::ofstream::binary);

        ifile.seekg(0, ifile.end);
        int length = ifile.tellg();
        ifile.seekg(0, ifile.beg);
        char * buffer = new char[++length];
        buffer[length - 1] = '\0';
        ifile.read((char*)buffer, length);

        std::string str;
        for (auto i = 0; i < length; ++i) {
            str += buffer[i];
        }

        succsess = checking_file(str);

        delete buffer;
        ifile.close();
        return succsess;
    }

    std::wstring to_LPCWSTR(const std::string& s)
    {
        int len;
        int slength = (int)s.length() + 1;
        len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
        wchar_t* buf = new wchar_t[len];
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
        std::wstring r(buf);
        delete[] buf;
        return r;
    }

    void check_registry() {
        HKEY hKey;
        std::vector< std::pair<std::string, std::string> > strings_of_regitry;

        if (RegOpenKeyEx(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), NULL, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
        {
            TCHAR lpData[1024] = { 0 };
            TCHAR data[1024] = { 0 };
            std::string str1, str2;
            DWORD buffersize = sizeof(lpData);
            DWORD num, MaxValueNameLen;

            RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &num, &MaxValueNameLen, NULL, NULL, NULL);

            for (DWORD i = 0; i < num; i++) {
                buffersize = MaxValueNameLen + 1;
                lpData[0] = '\0';
                data[0] = '\0';
                RegEnumValue(hKey, i, lpData, &buffersize, NULL, NULL, NULL, NULL);

                buffersize = 256;
                RegQueryValueEx(hKey, lpData, NULL, NULL, (LPBYTE)data, &buffersize);

                for (auto i = 0; lpData[i] != '\0'; ++i) {
                    str1 += lpData[i];
                }

                auto index = 0;
                if (data[0] == '\"') {
                    index = 1;
                }
                while (data[index] != '.' || data[index + 1] != 'e' || data[index + 2] != 'x' || data[index + 3] != 'e') {
                    str2 += data[index++];
                }
                str2 += data[index];
                str2 += data[index + 1];
                str2 += data[index + 2];
                str2 += data[index + 3];

                strings_of_regitry.push_back(std::make_pair(str1, str2));
                str1.clear();
                str2.clear();
            }
        }

        for (auto i : strings_of_regitry) {
            if (is_dangerous(i.second)) {

                std::wstring stemp1 = to_LPCWSTR(i.first);
                std::wstring stemp2 = to_LPCWSTR(i.second);
                LPCWSTR str1 = stemp1.c_str();
                LPCWSTR str2 = stemp2.c_str();

                RegDeleteValue(hKey, str1);
                RegDeleteKey(hKey, str2);

                move_file(path(i.second).generic_string(), path(i.second).filename().generic_string());
            }
        }

        RegCloseKey(hKey);
    }

public:

    void scan_filesystem() {
        read_data_of_dangerous_files();
        checking_dyrectory();
        check_registry();
    }

};

int main()
{
    antivirus_scaner scaner;
    scaner.scan_filesystem();

    return 0;
}
