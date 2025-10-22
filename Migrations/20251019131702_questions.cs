using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EngineeringThesis.Migrations
{
    /// <inheritdoc />
    public partial class questions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte[]>(
                name: "SecurityAnswerHash",
                table: "Users",
                type: "bytea",
                nullable: false,
                defaultValue: new byte[0]);

            migrationBuilder.AddColumn<byte[]>(
                name: "SecurityAnswerSalt",
                table: "Users",
                type: "bytea",
                nullable: false,
                defaultValue: new byte[0]);

            migrationBuilder.AddColumn<int>(
                name: "SecurityQuestion",
                table: "Users",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<bool>(
                name: "TwoFactorEnabled",
                table: "Users",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<byte[]>(
                name: "TwoFactorSecret",
                table: "Users",
                type: "bytea",
                nullable: false,
                defaultValue: new byte[0]);

            migrationBuilder.AddCheckConstraint(
                name: "CK_User_SecAnsHash_Len",
                table: "Users",
                sql: "octet_length(\"SecurityAnswerHash\") = 32");

            migrationBuilder.AddCheckConstraint(
                name: "CK_User_SecAnsSalt_Len",
                table: "Users",
                sql: "octet_length(\"SecurityAnswerSalt\") = 16");

            migrationBuilder.AddCheckConstraint(
                name: "CK_User_TotpSecret_Len",
                table: "Users",
                sql: "octet_length(\"TwoFactorSecret\") = 20");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_User_SecAnsHash_Len",
                table: "Users");

            migrationBuilder.DropCheckConstraint(
                name: "CK_User_SecAnsSalt_Len",
                table: "Users");

            migrationBuilder.DropCheckConstraint(
                name: "CK_User_TotpSecret_Len",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "SecurityAnswerHash",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "SecurityAnswerSalt",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "SecurityQuestion",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "TwoFactorEnabled",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "TwoFactorSecret",
                table: "Users");
        }
    }
}
