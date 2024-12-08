#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "bcrypt.lib")

#define SHA256_DIGEST_LENGTH 32
#define SHA256_STRING_LENGTH (SHA256_DIGEST_LENGTH * 2 + 1)

static long g_total_files = 0;     
static long g_processed_files = 0; 
static long g_skipped_files = 0;   // Atlanan dosya sayısı

static void print_progress(void) {
    fprintf(stdout, "\rİşlenen: %ld/%ld | Atlanan: %ld", g_processed_files, g_total_files, g_skipped_files);
    fflush(stdout);
}

static int hash_file(const WCHAR *filepath, char *hash_str) {
    if (!filepath || wcslen(filepath) == 0) {
        return -1;
    }

    HANDLE hFile = CreateFileW(filepath,
                               GENERIC_READ,
                               FILE_SHARE_READ,
                               NULL,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                               NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status != 0) {
        CloseHandle(hFile);
        return -1;
    }

    DWORD cbHashObject = 0, cbData = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(cbHashObject), &cbData, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlg,0);
        CloseHandle(hFile);
        return -1;
    }

    PBYTE pbHashObject = (PBYTE)malloc(cbHashObject);
    if (!pbHashObject) {
        BCryptCloseAlgorithmProvider(hAlg,0);
        CloseHandle(hFile);
        return -1;
    }

    BCRYPT_HASH_HANDLE hHash = NULL;
    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
    if (status != 0) {
        free(pbHashObject);
        BCryptCloseAlgorithmProvider(hAlg,0);
        CloseHandle(hFile);
        return -1;
    }

    unsigned char buffer[8192];
    DWORD bytesRead;
    BOOL bResult;

    do {
        bResult = ReadFile(hFile, buffer, (DWORD)sizeof(buffer), &bytesRead, NULL);
        if (!bResult) {
            BCryptDestroyHash(hHash);
            free(pbHashObject);
            BCryptCloseAlgorithmProvider(hAlg,0);
            CloseHandle(hFile);
            return -1;
        }

        if (bytesRead > 0) {
            status = BCryptHashData(hHash, buffer, bytesRead, 0);
            if (status != 0) {
                BCryptDestroyHash(hHash);
                free(pbHashObject);
                BCryptCloseAlgorithmProvider(hAlg,0);
                CloseHandle(hFile);
                return -1;
            }
        }
    } while (bResult && bytesRead > 0);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    status = BCryptFinishHash(hHash, hash, SHA256_DIGEST_LENGTH, 0);
    if (status != 0) {
        BCryptDestroyHash(hHash);
        free(pbHashObject);
        BCryptCloseAlgorithmProvider(hAlg,0);
        CloseHandle(hFile);
        return -1;
    }

    BCryptDestroyHash(hHash);
    free(pbHashObject);
    BCryptCloseAlgorithmProvider(hAlg,0);
    CloseHandle(hFile);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_str + (i * 2), "%02x", hash[i]);
    }
    hash_str[SHA256_STRING_LENGTH - 1] = '\0';
    return 0;
}

static int wchar_to_utf8(const WCHAR *wstr, char *buf, size_t bufsize) {
    if (!wstr || wcslen(wstr) == 0) {
        return -1;
    }
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, buf, (int)bufsize, NULL, NULL);
    if (len == 0) {
        return -1;
    }
    return 0;
}

static long count_files(const WCHAR *dirpath) {
    if (!dirpath || wcslen(dirpath) == 0) {
        return 0;
    }

    WCHAR search_path[MAX_PATH];
    if (_snwprintf_s(search_path, MAX_PATH, _TRUNCATE, L"%ls\\*", dirpath) < 0) {
        return 0;
    }

    WIN32_FIND_DATAW FindFileData;
    HANDLE hFind = FindFirstFileW(search_path, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }

    long file_count = 0;
    do {
        if (wcscmp(FindFileData.cFileName, L".") == 0 || wcscmp(FindFileData.cFileName, L"..") == 0) {
            continue;
        }

        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            continue;
        }

        WCHAR fullpath[MAX_PATH];
        if (_snwprintf_s(fullpath, MAX_PATH, _TRUNCATE, L"%ls\\%ls", dirpath, FindFileData.cFileName) < 0) {
            continue;
        }

        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            file_count += count_files(fullpath);
        } else {
            file_count += 1;
        }

    } while (FindNextFileW(hFind, &FindFileData) != 0);

    FindClose(hFind);
    return file_count;
}

// process_directory fonksiyonu bir önceki örnekte nasılsa aynen koruyun.
// Aynı şekilde kullanabilirsiniz.
static void process_directory(const WCHAR *dirpath, FILE *outf) {
    if (!dirpath || wcslen(dirpath) == 0) {
        return;
    }

    WCHAR search_path[MAX_PATH];
    if (_snwprintf_s(search_path, MAX_PATH, _TRUNCATE, L"%ls\\*", dirpath) < 0) {
        // Yol çok uzun -> atla
        g_skipped_files++;
        print_progress();
        return;
    }

    WIN32_FIND_DATAW FindFileData;
    HANDLE hFind = FindFirstFileW(search_path, &FindFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        // Dizin açılamadı -> atla
        g_skipped_files++;
        print_progress();
        return;
    }

    do {
        if (wcscmp(FindFileData.cFileName, L".") == 0 || wcscmp(FindFileData.cFileName, L"..") == 0) {
            continue;
        }

        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            g_skipped_files++;
            print_progress();
            continue;
        }

        WCHAR fullpath[MAX_PATH];
        if (_snwprintf_s(fullpath, MAX_PATH, _TRUNCATE, L"%ls\\%ls", dirpath, FindFileData.cFileName) < 0) {
            // Yol çok uzunsa atla
            g_skipped_files++;
            print_progress();
            continue;
        }

        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            process_directory(fullpath, outf);
        } else {
            char hash_str[SHA256_STRING_LENGTH];
            if (hash_file(fullpath, hash_str) == 0) {
                g_processed_files++;
                print_progress();
                char utf8_path[4*MAX_PATH]; 
                if (wchar_to_utf8(fullpath, utf8_path, sizeof(utf8_path)) == 0) {
                    fprintf(outf, "\"%s\",\"%s\"\n", utf8_path, hash_str);
                }
            } else {
                g_skipped_files++;
                print_progress();
            }
        }

    } while (FindNextFileW(hFind, &FindFileData) != 0);

    FindClose(hFind);
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // İstenilen davranış:
    // Tek argüman verilirse: Dosya kabul et, SHA256 hesapla, "<dosya>.sha256" olarak yaz.
    // İki argüman verilirse: Dizin kabul et, eski davranış (tüm dizini CSV'ye yaz).

    if (argc == 2) {
        // Tek dosya SHA256 hesaplama
        WCHAR wFilePath[MAX_PATH];
        int wlen = MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, wFilePath, MAX_PATH);
        if (wlen == 0 || wcslen(wFilePath) == 0) {
            fprintf(stderr, "Dosya yolu dönüştürülemedi veya çok uzun.\n");
            return 1;
        }

        // Dosyanın varlığı ve dosya olup olmadığı kontrolü
        DWORD attr = GetFileAttributesW(wFilePath);
        if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            fprintf(stderr, "Verilen yol bir dosya değil veya bulunamadı.\n");
            return 1;
        }

        char hash_str[SHA256_STRING_LENGTH];
        if (hash_file(wFilePath, hash_str) == 0) {
            // .sha256 uzantılı dosya oluştur
            char utf8_path[4*MAX_PATH];
            if (wchar_to_utf8(wFilePath, utf8_path, sizeof(utf8_path)) == 0) {
                char sha256_filename[4*MAX_PATH];
                snprintf(sha256_filename, sizeof(sha256_filename), "%s.sha256", utf8_path);

                FILE *sha256f = fopen(sha256_filename, "w");
                if (sha256f) {
                    fprintf(sha256f, "%s\n", hash_str);
                    fclose(sha256f);
                    printf("Hash hesaplandı ve '%s' dosyasına yazıldı.\n", sha256_filename);
                } else {
                    fprintf(stderr, "SHA256 doğrulama dosyası oluşturulamadı: %s\n", sha256_filename);
                }
            } else {
                fprintf(stderr, "UTF-8 dönüşümü hatası.\n");
            }
        } else {
            fprintf(stderr, "Dosyanın hash değeri hesaplanamadı.\n");
        }

        return 0;

    } else if (argc == 3) {
        // Dizin modu
        WCHAR wDirectory[MAX_PATH];
        int wdir_len = MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, wDirectory, MAX_PATH);
        if (wdir_len == 0) {
            fprintf(stderr, "Dizin yolu dönüştürülemedi veya çok uzun.\n");
            return 1;
        }

        if (wcslen(wDirectory) == 0) {
            fprintf(stderr, "Dizin yolu boş.\n");
            return 1;
        }

        const char *output_csv = argv[2];
        FILE *outf = fopen(output_csv, "w");
        if (!outf) {
            fprintf(stderr, "Çıktı dosyası açılamadı: %s\n", output_csv);
            return 1;
        }

        g_total_files = count_files(wDirectory);
        fprintf(stdout, "Gözlenecek dizin: %ls\n", wDirectory);
        fprintf(stdout, "Toplam %ld dosya işlenecek.\n", g_total_files);

        fprintf(outf, "\"path\",\"hash\"\n");

        print_progress();

        process_directory(wDirectory, outf);

        fclose(outf);

        fprintf(stdout, "\nİşleme tamamlandı. Toplam %ld dosya işlendi, %ld dosya atlandı.\n",
                g_processed_files, g_skipped_files);

        return 0;
    } else {
        fprintf(stderr, "Kullanım:\n");
        fprintf(stderr, "Tek dosya için: %s <dosya_yolu>\n", argv[0]);
        fprintf(stderr, "Dizin için: %s <dizin_yolu> <output_csv>\n", argv[0]);
        return 1;
    }
}
