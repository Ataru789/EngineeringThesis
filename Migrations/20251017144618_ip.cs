using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EngineeringThesis.Migrations
{
    /// <inheritdoc />
    public partial class ip : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RequestCity",
                table: "UserTokens");

            migrationBuilder.DropColumn(
                name: "RequestCountry",
                table: "UserTokens");

            migrationBuilder.DropColumn(
                name: "RequestLat",
                table: "UserTokens");

            migrationBuilder.DropColumn(
                name: "RequestLon",
                table: "UserTokens");

            migrationBuilder.DropColumn(
                name: "RequestUserAgent",
                table: "UserTokens");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RequestCity",
                table: "UserTokens",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RequestCountry",
                table: "UserTokens",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<double>(
                name: "RequestLat",
                table: "UserTokens",
                type: "double precision",
                nullable: true);

            migrationBuilder.AddColumn<double>(
                name: "RequestLon",
                table: "UserTokens",
                type: "double precision",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RequestUserAgent",
                table: "UserTokens",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);
        }
    }
}
