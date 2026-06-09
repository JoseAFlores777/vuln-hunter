// LAB vuln-hunter — vulnerabilidad PLANTADA (no usar en prod)
using System.Data.SqlClient;
public class UserRepo {
    public void Search(string term) {
        // PLANTADA: SQL injection por concatenacion (A03/A05, CWE-89) — Roslyn CA2100
        var sql = "SELECT * FROM Users WHERE Name LIKE '%" + term + "%'";
        using var cmd = new SqlCommand(sql);
    }
}
