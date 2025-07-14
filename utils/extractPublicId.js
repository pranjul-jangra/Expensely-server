export const extractPublicId = (url) => {
    const splitted = url.split("/");
    const folder = splitted.at(-2);
    const publicId = splitted.at(-1).split(".").at(-2);

    return `${folder}/${publicId}`;
} 