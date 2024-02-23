#include <iostream>
#include <phpcpp.h>
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/algorithm/string.hpp>
#include <algorithm>
#include <string>
#include <glob.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <functional>
#include <dirent.h>
#include <mcrypt.h>

/**
 *  tell the compiler that the get_module is a pure C function
 */

using namespace std;
string variable_name;
int counter = 0;

void GetReqDirs(const std::string &path, std::vector<string> &files, const bool showHiddenDirs = false)
{
    DIR *dpdf;
    struct dirent *epdf;
    dpdf = opendir(path.c_str());
    if (dpdf != NULL)
    {
        while ((epdf = readdir(dpdf)) != NULL)
        {
            if (showHiddenDirs ? (epdf->d_type == DT_DIR && string(epdf->d_name) != ".." && string(epdf->d_name) != ".") : (epdf->d_type == DT_DIR && strstr(epdf->d_name, "..") == NULL && strstr(epdf->d_name, ".") == NULL))
            {
                GetReqDirs(path + epdf->d_name + "/", files, showHiddenDirs);
            }
            if (epdf->d_type == DT_REG)
            {
                files.push_back(path + epdf->d_name);
            }
        }
    }
    closedir(dpdf);
}

bool CheckSubstring(std::string firstString, std::string secondString)
{
    if (secondString.size() > firstString.size())
        return false;

    for (size_t i = 0; i < firstString.size(); i++)
    {
        size_t j = 0;
        // If the first characters match
        if (firstString[i] == secondString[j])
        {
            int k = i;
            while (firstString[i] == secondString[j] && j < secondString.size())
            {
                j++;
                i++;
            }
            if (j == secondString.size())
                return true;
            else // Re-initialize i to its original value
                i = k;
        }
    }
    return false;
}

string random_string(int length)
{
    /*<< We first define the characters that we're going
         to allow.  This is pretty much just the characters
         on a standard keyboard.
    >>*/
    std::string tmp_s;
    std::string chars(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    /*<< We use __random_device as a source of entropy, since we want
         passwords that are not predictable.
    >>*/
    boost::random::random_device rng;
    /*<< Finally we select random characters from the
         string and append them to the result string.
    >>*/
    boost::random::uniform_int_distribution<> index_dist(0, chars.size() - 1);
    for (int i = 0; i < length; ++i)
    {
        tmp_s += chars[index_dist(rng)];
    }
    return tmp_s;
}

bool in_array(const string &needle, const vector<string> &haystack)
{
    int max = haystack.size();

    if (max == 0)
        return false;

    for (int i = 0; i < max; i++)
        if (haystack[i] == needle)
            return true;
    return false;
}

size_t strpos(const string &haystack, const string &needle)
{
    int sleng = haystack.length();
    int nleng = needle.length();

    if (sleng == 0 || nleng == 0)
        return string::npos;

    for (int i = 0, j = 0; i < sleng; j = 0, i++)
    {
        while (i + j < sleng && j < nleng && haystack[i + j] == needle[j])
            j++;
        if (j == nleng)
            return i;
    }
    return string::npos;
}

std::vector<std::string> glob(const std::string &pattern)
{
    glob_t glob_result = {0}; // zero initialize

    // do the glob operation
    int return_value = ::glob(pattern.c_str(), GLOB_TILDE, NULL, &glob_result);

    if (return_value != 0)
        throw std::runtime_error(std::strerror(errno));

    // collect all the filenames into a std::vector<std::string>
    // using the vector constructor that takes two iterators
    std::vector<std::string> filenames(
        glob_result.gl_pathv, glob_result.gl_pathv + glob_result.gl_pathc);

    // cleanup
    globfree(&glob_result);

    // done
    return filenames;
}

class Cryptix : public Php::Base
{
public:
    Cryptix() = default;
    virtual ~Cryptix() = default;

    //obfuscation
    static string obfuskasi(string codeAwal)
    {
        vector<string> variable_names_before;
        vector<string> variable_names_after;
        vector<string> function_names_before;
        vector<string> function_names_after;
        vector<string> forbidden_variables =
            {"$GLOBALS", "$_SERVER", "$_GET", "$_POST", "$_FILES",
             "$_COOKIE", "$_SESSION", "$_REQUEST", "$_ENV"
            };

        vector<string> forbidden_functions = {"unlink"};

        string file_contents = codeAwal;
        bool lock = false;
        string lock_quote = "";
        for (size_t i = 0; i < file_contents.size(); i++)
        {
            // check if there are quotation marks
            string comparestring(1, file_contents.at(i));
            if ((comparestring.compare("'") || file_contents.at(i) == '"'))
            {
                // if first quote
                if (lock_quote == "")
                {
                    // remember quotation mark
                    lock_quote = file_contents.at(i);
                    lock = true;
                }
                else if (comparestring.compare(lock_quote))
                {
                    lock_quote = "";
                    lock = false;
                }
            }
            //cout <<"check quatation marks passed"<<endl;

            // detect variables
            if (!lock && file_contents.at(i) == '$')
            {
                int start = i;
                // detect variable variable names

                if (file_contents.at(i + 1) == '$')
                {
                    start++;
                    i++;
                }

                int end = 1;
                // find end of variable name
                while (isalpha(file_contents.at(start + end)) || isdigit(file_contents.at(start + end)) || file_contents.at(start + end) == '_')
                {
                    end++;
                }
                // extract variable name
                variable_name = file_contents.substr(start, end);

                if (variable_name == "$")
                {
                    continue;
                }

                // check if variable name is allowed
                if (in_array(variable_name, forbidden_variables))
                {
                }
                else
                {

                    // check if variable name already has been detected
                    if (!in_array(variable_name, variable_names_before))
                    {
                        variable_names_before.push_back(variable_name);

                        string new_variable_name = "";
                        do
                        {
                            new_variable_name = random_string();
                        } while (in_array(new_variable_name, variable_names_after));
                        variable_names_after.push_back(new_variable_name);
                    }
                }
            }
            //cout <<"check variable"<< i << "passed"<<endl;
            
            // detect function-definitions
            // the third condition checks if the symbol before 'function' is neither a character nor a number
            if (!lock && file_contents.substr(i, 8) == "function" && (!isalpha(file_contents[i - 1]) && !isdigit(file_contents[i - 1])))
            {
                // find end of function name
                int end = file_contents.find('(', i);
                // extract function name and remove possible spaces on the right side
                string function_name_helper = file_contents.substr((i + 9), (end - i - 9));
                boost::trim_right(function_name_helper);
                string function_name = function_name_helper;
                // check if function name is allowed
                if (in_array(function_name, forbidden_functions))
                {
                }
                else
                {
                    if (!in_array(function_name, function_names_before))
                    {
                        function_names_before.push_back(function_name);
                        //cout << "nama fungsi yang terdeteksi:" << function_name << endl;

                        // generate random name for variable
                        string new_function_name = "";
                        do
                        {

                            new_function_name = random_string();

                        } while (in_array(new_function_name, function_names_after));
                        function_names_after.push_back(new_function_name);
                    }
                }
            }
            //cout <<"check function "<< i << "passed"<<endl;
        }


        // this array contains prefixes and suffixes for string literals which
        // may contain variable names.
        // if string literals as a return of functions should not be changed
        // remove the last two inner arrays of $possible_pre_suffixes
        // this will enable correct handling of situations like
        // - $func = 'getNewName'; echo $func();
        // but it will break variable variable names like
        // - ${getNewName()}

        // Two-dimensional key
        map<int, map<string, string>> possible_pre_suffixes;
        possible_pre_suffixes[0] = {{"prefix", "= '"}, {"suffix", "'"}};
        possible_pre_suffixes[1] = {{"prefix", "=\""}, {"suffix", "\""}};
        possible_pre_suffixes[2] = {{"prefix", "='"}, {"suffix", "'"}};
        possible_pre_suffixes[3] = {{"prefix", "=\""}, {"suffix", "\""}};
        possible_pre_suffixes[4] = {{"prefix", "rn \""}, {"suffix", "\""}};
        possible_pre_suffixes[5] = {{"prefix", "rn '"}, {"suffix", "'"}};

        // replace variable name

        for (size_t i = 0; i < variable_names_before.size(); i++)
        {
            string dolar = "$";
            string helper = dolar.append(variable_names_after[i]);
            boost::algorithm::replace_all(file_contents, variable_names_before[i], helper);
            string name = variable_names_before[i].substr(1);

            for (size_t j = 0; j < possible_pre_suffixes.size(); j++)
            {
                string helpera = possible_pre_suffixes[j]["prefix"].append(name).append(possible_pre_suffixes[j]["suffix"]);
                string helperb = possible_pre_suffixes[j]["prefix"].append(variable_names_after[i]).append(possible_pre_suffixes[j]["suffix"]);
                boost::algorithm::replace_all(file_contents, helpera, helperb);
            }
        }
        //cout <<"replace variable name passed"<<endl;


        // replace funciton names
        for (size_t i = 0; i < function_names_before.size(); i++)
        {
            // cout << file_contents.size()<<endl;
            //cout << "before ++> "<<function_names_before[i] << " %% "<< "after ++> "<<function_names_after[i]<<endl;
            boost::algorithm::replace_all(file_contents, function_names_before[i], function_names_after[i]);
            //cout <<"process ["<<i<< "] replace function name passed"<<endl;
            
        }
        //cout <<"replace function name passed"<<endl;

        return file_contents;
    }

    static void obfuscation(Php::Parameters &params)
    {
        std::string type = "blowfish";
        std::string file = params[0];

        if (params.size() != 1)
        {
            cout << "PHPCryptonext : You need to supply one argument to this program.\n";
        }
        else
        {
            string codeAwal = Php::call("file_get_contents", file, true);

            string hasil = obfuskasi(codeAwal);
            std::string enc_code = "<?php PHPCryptonext::decode('" + type + "', '" + blowfish_enc(type, hasil) + "'); ?>";
            Php::out << Php::call("file_put_contents", file + ".original", codeAwal) << std::endl;
            Php::out << Php::call("file_put_contents", file, enc_code) << std::endl;
            Php::out << Php::call("file_put_contents", file + ".obfuskasi", hasil) << std::endl;
        }
    }

    static void obfus(Php::Parameters &params)
    {
        std::string type = "blowfish";
        std::string path = params[0];

        vector<string> listfile;
        vector<string> res;

        GetReqDirs(path, listfile);

        for (string file : listfile)
        {
            if (CheckSubstring(file, ".php"))
            {
                res.push_back(file);
            }
        }

        string input, coba, str3, akhir, enc_code;
        string name[res.size()];
        string gabungan = "potong";
        string nama,hasil;
        vector<string> penanda;
        for (size_t i = 0; i < res.size(); i++)
        {
            akhir = gabungan + to_string(i);
            penanda.push_back(akhir);
        }
        int cnt = 0;
        int i = 0;
        for (string data : res)
        {

            string nama = Php::call("basename", data);
            name[cnt] = nama;
            string hasil = Php::call("file_get_contents", data);
            Php::out << Php::call("file_put_contents", res.at(i) + ".orignal", hasil) << std::endl;
            cnt++;
            //hitung = to_string(cnt);

            if ((size_t)cnt < res.size())
            {
                input += hasil + "\n" + penanda.at(i) + "\n";
                i++;
            }
            else if ((size_t)cnt == res.size())
            {
                input += hasil;
            }
             coba = obfuskasi(input);
            
        }

        int counter = 0;
        size_t npos = 0;
        for (size_t i = 0; i < res.size(); i++)
        {
            if (i < res.size() - 1)
            {
                std::size_t pos = coba.find(penanda.at(i)); // position of "end" in coba
                npos = pos - counter;
                str3 = coba.substr(counter, npos);

                //Php::out << Php::call("file_put_contents", res.at(i) + ".obfuskasi", str3) << std::endl;
                enc_code = "<?php PHPCryptonext::decode('" + type + "', '" + blowfish_enc(type, str3) + "'); ?>";
                Php::out << Php::call("file_put_contents", res.at(i), enc_code) << std::endl;

                counter = pos + penanda.at(i).length();
            }
            else
            {

                std::size_t pos = coba.length();
                str3 = coba.substr(counter, pos);
                //Php::out << Php::call("file_put_contents", res.at(i) + ".obfuskasi", str3) << std::endl;
                enc_code = "<?php PHPCryptonext::decode('" + type + "', '" + blowfish_enc(type, str3) + "'); ?>";
                Php::out << Php::call("file_put_contents", res.at(i), enc_code) << std::endl;
            }

        }
    }

    static void decrypt(Php::Parameters &params)
    {
        // @todo add implementation
        std::string type = params[0];
        std::string msg = params[1];

        // :TODO kondisi jika tidak ada close tag
        std::string plain_code = blowfish_dec(type, msg);
        std::string clean_code = Php::call("rtrim", plain_code);

        // get close tag
        std::string end_code = Php::call("substr", clean_code, -2);
        std::string sanitize_code = Php::call("substr", clean_code, 0, -2);

        // standard code is omitting close php tag
        std::string standard_code;
        if (end_code == "?>")
        {
            // remove closing tag
            standard_code = sanitize_code;
        }
        else
        {
            standard_code = clean_code;
        }

        std::string code = " ?>" + standard_code;
        Php::out << Php::eval(code) << std::endl;
    }

    static void encrypt(Php::Parameters &params)
    {
        // @todo add implementation
        std::string type = params[0];
        std::string msg = params[1];
        // if(type=="blowfish"){
        Php::out << blowfish_enc(type, msg) << std::endl;
        // }
    }

    static std::string blowfish_enc(std::string data, std::string key)
    {
        // Get IV length
        int ivSize = mcrypt_enc_get_iv_size(MCRYPT_BLOWFISH);
        char *iv = new char[ivSize];
        // Generate random IV
        for (int i = 0; i < ivSize; ++i)
        {
            iv[i] = rand() % 256;
        }

        // Create encryption handle
        MCRYPT cipher = mcrypt_module_open(MCRYPT_BLOWFISH, NULL, "cbc", NULL);
        if (cipher == MCRYPT_FAILED)
        {
            throw std::runtime_error("Failed to initialize Blowfish encryption module");
        }

        // Initialize encryption
        int result = mcrypt_generic_init(cipher, key.c_str(), key.size(), iv);
        if (result < 0)
        {
            throw std::runtime_error("Failed to initialize Blowfish encryption");
        }

        // Get required buffer size
        size_t dataSize = data.size();
        size_t bufferSize = dataSize + ivSize;
        char *buffer = new char[bufferSize];

        // Copy IV to buffer
        memcpy(buffer, iv, ivSize);

        // Encrypt data
        result = mcrypt_generic(cipher, (void *)data.c_str(), dataSize, buffer + ivSize, bufferSize - ivSize);
        if (result != 0)
        {
            throw std::runtime_error("Failed to perform Blowfish encryption");
        }

        // Clean up
        mcrypt_generic_deinit(cipher);
        mcrypt_module_close(cipher);
        delete[] iv;

        // Convert encrypted data to base64
        std::string encryptedData(buffer, bufferSize);
        delete[] buffer;
        return base64_encode(encryptedData);
    }

    static std::string blowfish_dec(std::string cipher, std::string key)
    {
        // Decode base64
        std::string decodedCipher = base64_decode(cipher);

        // Get IV length
        int ivSize = mcrypt_enc_get_iv_size(MCRYPT_BLOWFISH);
        if (decodedCipher.size() < ivSize)
        {
            throw std::runtime_error("Invalid cipher text");
        }

        // Extract IV
        char *iv = new char[ivSize];
        memcpy(iv, decodedCipher.c_str(), ivSize);

        // Create decryption handle
        MCRYPT cipherHandle = mcrypt_module_open(MCRYPT_BLOWFISH, NULL, "cbc", NULL);
        if (cipherHandle == MCRYPT_FAILED)
        {
            throw std::runtime_error("Failed to initialize Blowfish decryption module");
        }

        // Initialize decryption
        int result = mcrypt_generic_init(cipherHandle, key.c_str(), key.size(), iv);
        if (result < 0)
        {
            throw std::runtime_error("Failed to initialize Blowfish decryption");
        }

        // Decrypt data
        size_t dataSize = decodedCipher.size() - ivSize;
        char *decryptedData = new char[dataSize];
        result = mdecrypt_generic(cipherHandle, (void *)(decodedCipher.c_str() + ivSize), dataSize, decryptedData, dataSize);
        if (result != 0)
        {
            throw std::runtime_error("Failed to perform Blowfish decryption");
        }

        // Clean up
        mcrypt_generic_deinit(cipherHandle);
        mcrypt_module_close(cipherHandle);
        delete[] iv;

        // Return decrypted data
        std::string plaintext(decryptedData, dataSize);
        delete[] decryptedData;
        return plaintext;
    }

private:
    static std::string base64_encode(const std::string &plainText)
    {
        // Encode plain text using base64
        Php::Value base64Encode = Php::call("base64_encode", plainText);
        return base64Encode.stringValue();
    }

    static std::string base64_decode(const std::string &base64Text)
    {
        // Decode base64 text
        Php::Value base64Decode = Php::call("base64_decode", base64Text);
        return base64Decode.stringValue();
    }
};

extern "C"
{

    PHPCPP_EXPORT void *get_module()
    {
        static Php::Extension extension("phpcryptonext", "1.0");

        Php::Class<Cryptix> myCrypt("PHPCryptonext");
        myCrypt.method<&Cryptix::decrypt>("decode");
        myCrypt.method<&Cryptix::encrypt>("encode");
        myCrypt.method<&Cryptix::obfuscation>("singleobfuscation");
        myCrypt.method<&Cryptix::obfus>("directoryobfuscation");
        extension.add(std::move(myCrypt));

        return extension;
    }
}
